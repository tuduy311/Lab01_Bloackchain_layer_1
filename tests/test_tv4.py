# %% [markdown]
# TV4: integration and regression tests.
# Run: python -m pytest tests/test_tv4.py -v
# The # %% markers also allow opening sections as interactive Python cells.

# %% Imports and fixtures
"""Integration tests with real Ed25519 signatures and independent node states."""

import json
import re
import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.blockchain_simulator import BlockchainSimulator, SimulationConfig
from src.consensus.locking import Polka
from src.consensus.timeout import TimeoutConfig
from src.crypto import ValidatorKeyStore, sha256_hex, sign_block, sign_vote, verify_vote_signature
from src.execution import apply_transaction, validate_block, validate_transaction
from src.models import Block, FinalizeCertificate, NIL_BLOCK_ID, Phase, ValidatorSet, Vote, _canonical_json
from src.network import KIND_BODY_REQUEST, NetworkConfig, NetworkEnvelope, SendStatus
from src.scheduler import Scheduler


def make_simulator(num_nodes=4, seed=7, **kwargs):
    network = kwargs.pop("network", NetworkConfig(min_delay=0.001, max_delay=0.01))
    timeout = kwargs.pop("timeout", TimeoutConfig(base=0.2, multiplier=1.5, max_timeout=2))
    return BlockchainSimulator(SimulationConfig(
        num_nodes=num_nodes, seed=seed, network=network, timeout=timeout,
        gossip_interval=0.05, **kwargs,
    ))


def empty_block(sim, height=1, round_=0, state_root=None):
    proposer = sim.selector.proposer_for(height, round_)
    node = sim.nodes[proposer]
    return sign_block(Block(
        height=height, round=round_, parent_id=node.chain[node.committed_height].block_id,
        proposer_id=proposer, state_root=state_root or node.world_state.state_root(),
    ), sim.key_store.private_key(proposer))


def signed_vote(sim, voter, phase, block_id, height=1, round_=0):
    return sim.key_store.sign_vote_as(Vote(height, round_, phase, block_id, voter), voter)


def certificate(sim, block, round_=0, voters=None):
    voters = voters or sim.node_ids[:sim.selector.quorum]
    return FinalizeCertificate(block.height, round_, block.block_id, tuple(
        signed_vote(sim, voter, Phase.PRECOMMIT, block.block_id, block.height, round_)
        for voter in voters
    ))


# %% Node state, transaction validation and certificate verification
class TestNode:
    def test_states_are_independent(self):
        sim = make_simulator()
        address = sim.public_keys["node_1"]
        sim.nodes["node_1"].world_state.debit(address, 10)
        assert sim.nodes["node_2"].world_state.get_balance(address) == 1000
        assert sim.genesis_state.get_balance(address) == 1000

    def test_invalid_and_duplicate_transactions(self):
        sim = make_simulator()
        tx = sim.make_transaction("node_1", "node_2", 10, 0)
        node = sim.nodes["node_1"]
        assert node.submit_transaction(tx)
        assert not node.submit_transaction(tx)
        assert not node.submit_transaction(replace(tx, amount=11))
        assert not node.submit_transaction(replace(tx, amount=-1))
        assert not node.submit_transaction(replace(tx, signature="broken"))
        assert node.world_state.get_balance(tx.sender) == 1000

    def test_commit_is_exactly_once(self):
        sim = make_simulator()
        tx = sim.make_transaction("node_1", "node_2", 30, 0)
        sim.submit_transaction(tx)
        assert sim.run(1).completed
        node = sim.nodes["node_1"]
        before = node.world_state.to_dict()
        assert not node.commit_finalized_block(node.chain[1], node.certificates[1])
        assert node.world_state.to_dict() == before
        assert node.world_state.get_balance(tx.sender) == 970
        assert node.world_state.get_nonce(tx.sender) == 1
        assert not node.mempool

    @pytest.mark.parametrize("mode", ["too_few", "duplicate", "bad_signature", "wrong_block", "wrong_phase"])
    def test_reject_invalid_certificate(self, mode):
        sim = make_simulator()
        block = empty_block(sim)
        cert = certificate(sim, block)
        votes = list(cert.precommits)
        if mode == "too_few":
            cert = replace(cert, precommits=tuple(votes[:-1]))
        elif mode == "duplicate":
            cert = replace(cert, precommits=(votes[0],) * len(votes))
        elif mode == "bad_signature":
            votes[0] = replace(votes[0], signature="00")
            cert = replace(cert, precommits=tuple(votes))
        elif mode == "wrong_block":
            cert = replace(cert, block_id="forged")
        else:
            votes[0] = signed_vote(sim, votes[0].voter_id, Phase.PREVOTE, block.block_id)
            cert = replace(cert, precommits=tuple(votes))
        node = sim.nodes["node_1"]
        assert not node.commit_finalized_block(block, cert)
        assert node.committed_height == 0

    def test_certificate_cannot_bypass_block_execution(self):
        sim = make_simulator()
        block = empty_block(sim, state_root="forged-root")
        node = sim.nodes["node_1"]
        before = node.world_state.to_dict()
        assert not node.commit_finalized_block(block, certificate(sim, block))
        assert node.world_state.to_dict() == before
        assert node.engine.height == 1

    def test_malformed_and_impersonated_envelopes_are_rejected(self):
        sim = make_simulator()
        node = sim.nodes["node_1"]
        node.start()
        vote = signed_vote(sim, "node_2", Phase.PREVOTE, "unknown")
        for payload in [None, {"invalid": True}, vote.to_dict()]:
            node.on_receive(node.node_id, NetworkEnvelope(
                "injected", "PREVOTE", "node_3", node.node_id, payload, 0, 0, height=1,
            ))
        assert len([e for e in node.events if e["event"] == "REJECT_MESSAGE"]) == 3
        assert not node.engine.votes.votes(1, 0, Phase.PREVOTE)
        node.stop()

    def test_future_height_finalization_waits_for_parent(self):
        sim = make_simulator()
        assert sim.run(2).completed
        source = sim.nodes["node_1"]
        fresh = make_simulator().nodes["node_2"]
        assert not fresh.commit_finalized_block(source.chain[2], source.certificates[2])
        assert fresh.committed_height == 0
        assert fresh.commit_finalized_block(source.chain[1], source.certificates[1])
        fresh._drain_pending()
        assert fresh.committed_height == 2
        assert fresh.world_state.state_root() == source.chain[2].state_root


# %% Consensus regressions exposed by integration
class TestConsensusIntegration:
    def test_local_vote_completes_quorum_and_extra_prevote_is_idempotent(self):
        sim = make_simulator()
        engine = sim.nodes["node_1"].engine
        block = empty_block(sim)
        assert engine.accept_proposal(block)
        for voter in ("node_2", "node_3"):
            assert engine.receive_vote(signed_vote(sim, voter, Phase.PREVOTE, block.block_id)) is None
        local = engine.make_prevote(block.block_id)
        assert verify_vote_signature(local, sim.public_keys["node_1"])
        actions = engine.poll()
        assert len(actions) == 1 and actions[0].phase == Phase.PRECOMMIT
        assert verify_vote_signature(actions[0], sim.public_keys["node_1"])
        assert engine.receive_vote(signed_vote(sim, "node_4", Phase.PREVOTE, block.block_id)) is None
        assert engine.poll() == ()

    def test_reordered_precommits_are_revisited_after_polka(self):
        sim = make_simulator()
        engine = sim.nodes["node_1"].engine
        block = empty_block(sim)
        assert engine.accept_proposal(block)
        for voter in ("node_2", "node_3"):
            assert engine.receive_vote(signed_vote(sim, voter, Phase.PRECOMMIT, block.block_id)) is None
        engine.make_prevote(block.block_id)
        for voter in ("node_2", "node_3"):
            engine.receive_vote(signed_vote(sim, voter, Phase.PREVOTE, block.block_id))
        actions = engine.poll()
        assert any(isinstance(action, FinalizeCertificate) for action in actions)
        assert engine.height == 2

    def test_unknown_block_and_forged_votes_cannot_finalize(self):
        sim = make_simulator()
        engine = sim.nodes["node_1"].engine
        for voter in sim.node_ids:
            for phase in (Phase.PREVOTE, Phase.PRECOMMIT):
                engine.receive_vote(signed_vote(sim, voter, phase, "missing-body"))
        assert engine.poll() == ()
        assert not engine.polkas and not engine.finalized
        forged = replace(signed_vote(sim, "node_2", Phase.PREVOTE, "another"), voter_id="node_3")
        assert engine.receive_vote(forged) is None
        assert engine.votes.count(1, 0, Phase.PREVOTE, "another") == 0

    def test_locked_block_reproposal_keeps_original_id(self):
        sim = make_simulator()
        engine = sim.nodes["node_1"].engine
        block = empty_block(sim)
        assert engine.accept_proposal(block)
        engine.make_prevote(block.block_id)
        for voter in ("node_2", "node_3"):
            engine.receive_vote(signed_vote(sim, voter, Phase.PREVOTE, block.block_id))
        proof = engine.polkas[(1, 0, block.block_id)]
        assert engine.on_timeout(1, 0)
        leader = sim.selector.proposer_for(1, 1)
        assert not engine.accept_proposal(block, proposal_round=1, proposer_id=leader)
        assert engine.accept_proposal(block, proposal_round=1, proposer_id=leader, valid_round_polka=proof)
        assert engine.make_prevote(block.block_id).block_id == block.block_id
        assert engine.lock.locked_block_id == block.block_id

    def test_old_block_id_cannot_finalize_at_new_height(self):
        sim = make_simulator()
        assert sim.run(1).completed
        node = sim.nodes["node_1"]
        old_id = node.chain[1].block_id
        for phase in (Phase.PREVOTE, Phase.PRECOMMIT):
            for voter in sim.node_ids:
                assert node.engine.receive_vote(signed_vote(
                    sim, voter, phase, old_id, height=2,
                )) is None
        assert node.engine.poll() == ()
        assert node.engine.height == 2 and 2 not in node.engine.finalized

    def test_forged_polka_does_not_unlock(self):
        sim = make_simulator()
        engine = sim.nodes["node_1"].engine
        engine.lock.locked_block_id, engine.lock.locked_round = "locked", 0
        engine.on_timeout(1, 0)
        block = empty_block(sim)
        proof = Polka(1, 0, block.block_id, tuple(
            signed_vote(sim, "node_2", Phase.PREVOTE, block.block_id) for _ in range(3)
        ))
        assert not engine.accept_proposal(block, proposal_round=1,
            proposer_id=sim.selector.proposer_for(1, 1), valid_round_polka=proof)
        assert engine.lock.locked_block_id == "locked"

    def test_eight_node_quorum_has_honest_intersection(self):
        sim = make_simulator(8)
        assert sim.selector.quorum == 6
        assert sim.nodes["node_1"].engine.quorum == 6
        assert ValidatorSet(sim.node_ids, f=2).quorum == 6
        assert 2 * sim.selector.quorum - len(sim.node_ids) > 2


# %% End-to-end runs with delayed/duplicated/lost messages and node faults
class TestBlockchainSimulator:
    @pytest.mark.parametrize("size", [1, 4, 8, 10])
    def test_multiple_heights_and_signed_certificates(self, size):
        sim = make_simulator(size)
        result = sim.run(3)
        assert result.completed and result.stop_reason == "target_height"
        chains = [tuple(sim.nodes[n].chain[h].block_id for h in range(1, 4)) for n in sim.correct_nodes]
        assert len(set(chains)) == 1
        for node in sim.nodes.values():
            for cert in node.certificates.values():
                assert len({v.voter_id for v in cert.precommits}) >= node.engine.quorum
                assert all(verify_vote_signature(v, sim.public_keys[v.voter_id]) for v in cert.precommits)
            assert node.timeout_manager.active_slot is None
        sim.assert_invariants()

    def test_transfers_nonces_and_block_capacity(self):
        sim = make_simulator(max_transactions=1)
        tx1 = sim.make_transaction("node_1", "node_2", 100, 0)
        tx2 = sim.make_transaction("node_1", "node_2", 50, 1)
        overdraw = sim.make_transaction("node_3", "node_2", 1001, 0)
        for tx in (tx1, tx2, overdraw):
            assert all(sim.submit_transaction(tx).values())
        assert sim.run(3).completed
        for node in sim.nodes.values():
            assert node.world_state.get_balance(tx1.sender) == 850
            assert node.world_state.get_balance(tx1.receiver) == 1150
            assert node.world_state.get_nonce(tx1.sender) == 2
            assert node.world_state.get_nonce(overdraw.sender) == 0
            assert all(len(block.transactions) <= 1 for block in node.chain.values())

    def test_scheduled_transaction_and_resuming_run(self):
        sim = make_simulator()
        tx = sim.make_transaction("node_1", "node_2", 15, 0)
        sim.schedule_transaction(0.01, tx)
        first = sim.run(1)
        assert first.completed
        assert any(e["event"] == "TX_ADMITTED" and e["time"] == 0.01 for e in sim.log)
        result = sim.run(5, max_simulation_time=5)
        assert result.completed
        assert all(node.world_state.get_balance(tx.sender) == 985 for node in sim.nodes.values())

    @pytest.mark.parametrize("seed", [1, 7, 11, 23])
    def test_loss_duplication_reordering_and_stabilization(self, seed):
        sim = make_simulator(8, seed, network=NetworkConfig(
            min_delay=0.001, max_delay=0.025, drop_rate=0.2,
            duplicate_rate=0.6, stabilize_at=0.8, pre_synchrony_max_delay=0.08,
        ))
        tx = sim.make_transaction("node_1", "node_2", 20, 0)
        sim.submit_transaction(tx)
        result = sim.run(3, max_simulation_time=10)
        assert result.completed
        assert result.network_counters["duplicates_created"] > 0
        assert result.network_counters["dropped"] > 0
        for node in sim.nodes.values():
            assert node.world_state.get_balance(tx.sender) == 980
            assert node.world_state.get_nonce(tx.sender) == 1
        sim.assert_invariants()

    def test_silent_first_proposer_rotates_after_timeout(self):
        sim = make_simulator()
        first_leader = sim.selector.proposer_for(1, 0)
        sim.nodes[first_leader].silent_proposer = True
        assert sim.run(2).completed
        assert all(node.certificates[1].round >= 1 for node in sim.nodes.values())
        assert any(record["event"] == "TIMEOUT" for record in sim.log)

    def test_invalid_signed_proposal_is_rejected_then_next_leader_progresses(self, monkeypatch):
        sim = make_simulator()
        leader = sim.nodes[sim.selector.proposer_for(1, 0)]
        bad = empty_block(sim, state_root="incorrect-state-root")
        original = leader.propose_block

        def invalid_proposal():
            if (leader.engine.height, leader.engine.round) != (1, 0):
                return original()
            header = leader._make_header("PROPOSAL", bad, 0)
            leader._announce(header, bad)
            leader._handle_proposal(header, bad)
            return bad

        monkeypatch.setattr(leader, "propose_block", invalid_proposal)
        assert sim.run(1).completed
        assert all(node.chain[1].block_id != bad.block_id for node in sim.nodes.values())
        assert any(e["event"] == "REJECT_PROPOSAL" for e in sim.log)

    def test_all_block_transfers_have_an_accepted_header(self):
        sim = make_simulator(8)
        assert sim.run(2).completed
        accepted = set()
        bodies = 0
        for event in sim.network.events:
            if event.event == "HEADER_ACCEPT":
                accepted.add((event.node_id, event.header_id))
            elif event.event == "DELIVER" and event.kind == "BODY":
                assert (event.peer_id, event.header_id) in accepted
                bodies += 1
        assert bodies > 0

    def test_gossip_does_not_deadlock_on_repeated_polka_advertisements(self):
        # Previously, every old polka was re-sent every 50ms. Honest peers
        # exceeded inbound limits and repeatedly blocked each other forever.
        sim = make_simulator(4, 11, network=NetworkConfig(
            min_delay=0.001, max_delay=0.03, drop_rate=0.25, duplicate_rate=0.5,
            stabilize_at=0.8, pre_synchrony_max_delay=0.1,
        ))
        assert sim.nodes["node_1"].gossip_interval >= 0.05
        assert sim.run(3, max_simulation_time=10).completed

    @pytest.mark.parametrize("size,faults", [(4, 1), (8, 2)])
    def test_permanently_crashed_first_proposer(self, size, faults):
        sim = make_simulator(size)
        crashed = [sim.selector.proposer_for(1, round_) for round_ in range(faults)]
        for node in crashed:
            sim.schedule_crash(node, 0)
        result = sim.run(2)
        assert result.completed
        assert all(sim.nodes[node].committed_height == 0 for node in crashed)
        assert all(sim.nodes[node].committed_height >= 2 for node in sim.correct_nodes)

    def test_recovered_node_catches_up_via_header_body_and_certificates(self):
        sim = make_simulator()
        recovering = sim.selector.proposer_for(1, 0)
        tx = sim.make_transaction("node_1", "node_2", 25, 0)
        sim.submit_transaction(tx)
        sim.schedule_crash(recovering, 0, recover_at=0.7)
        result = sim.run(3, max_simulation_time=10)
        assert result.completed and not sim.nodes[recovering].crashed
        assert sim.nodes[recovering].committed_height >= 3
        assert sim.nodes[recovering].world_state.get_nonce(tx.sender) == 1
        assert any(r["event"] == "RECOVER" for r in result.log)
        sim.assert_invariants()

    def test_timeout_after_lock_reproposes_same_block(self, monkeypatch):
        sim = make_simulator()
        original_send = sim.network._send_one

        def drop_early_precommits(sender, recipient, payload, kind, height, header_id):
            if kind == "PRECOMMIT" and sim.scheduler.now < 0.25:
                return SendStatus.MESSAGE_DROPPED
            return original_send(sender, recipient, payload, kind, height, header_id)

        monkeypatch.setattr(sim.network, "_send_one", drop_early_precommits)
        result = sim.run(1, max_simulation_time=5)
        assert result.completed
        for node in sim.nodes.values():
            assert node.chain[1].round == 0
            assert node.certificates[1].round >= 1

    def test_replay_produces_byte_identical_logs_and_keys(self):
        def run(seed):
            sim = make_simulator(4, seed, network=NetworkConfig(
                drop_rate=0.1, duplicate_rate=0.3, min_delay=0.001, max_delay=0.03,
                stabilize_at=0.5,
            ))
            sim.submit_transaction(sim.make_transaction("node_1", "node_2", 10, 0))
            result = sim.run(2)
            assert result.completed
            return json.dumps(result.to_dict(), sort_keys=True, separators=(",", ":")), sim.public_keys

        log_a, keys_a = run(9)
        log_b, keys_b = run(9)
        log_c, keys_c = run(10)
        assert log_a == log_b and keys_a == keys_b
        assert log_a != log_c and keys_a != keys_c

    @pytest.mark.parametrize("bound", ["time", "events"])
    def test_no_quorum_stops_at_explicit_bound(self, bound):
        sim = make_simulator(network=NetworkConfig(drop_rate=1))
        kwargs = {"max_simulation_time": 0.3} if bound == "time" else {"max_events": 20}
        result = sim.run(1, **kwargs)
        assert not result.completed
        if bound == "time":
            assert result.stop_reason == "max_simulation_time"
            assert result.simulation_time == pytest.approx(0.3)
        else:
            assert result.stop_reason == "max_events" and result.processed_events == 20
        assert all(node.committed_height == 0 for node in sim.nodes.values())

    @pytest.mark.parametrize("kwargs", [
        {"num_nodes": 0}, {"gossip_interval": 0}, {"initial_balances": {"node_1": -1}},
        {"faulty_nodes": ("missing",)}, {"max_transactions": 0},
    ])
    def test_invalid_simulation_config(self, kwargs):
        with pytest.raises(ValueError):
            BlockchainSimulator(SimulationConfig(**kwargs))


# %% Scheduler and seeded-key regressions
class TestSupportingRegressions:
    def test_cancelled_root_does_not_cross_run_until_boundary(self):
        scheduler = Scheduler()
        seen = []
        cancelled = scheduler.schedule_at(0.1, seen.append, "cancelled")
        scheduler.schedule_at(2, seen.append, "late")
        scheduler.cancel(cancelled)
        assert scheduler.run_until(1) == 0
        assert scheduler.now == 1 and seen == []
        assert scheduler.peek_time() == 2

    def test_peek_uses_minimum_live_event_after_cancellation(self):
        scheduler = Scheduler()
        root = scheduler.schedule_at(1, lambda: None)
        for time in (4, 2, 5, 6, 3):
            scheduler.schedule_at(time, lambda: None)
        scheduler.cancel(root)
        assert scheduler.peek_time() == 2

    def test_seeded_keystore_preserves_unseeded_api(self):
        a = ValidatorKeyStore(["a", "b"], seed=123)
        b = ValidatorKeyStore(["a", "b"], seed=123)
        c = ValidatorKeyStore(["a", "b"], seed=124)
        assert a.public_keys == b.public_keys and a.public_keys != c.public_keys
        assert ValidatorKeyStore(["a"]).public_keys != ValidatorKeyStore(["a"]).public_keys


# %% Acceptance matrix from the assignment image: T1--T7
# Existing coverage:
# T1: TestBlockchainSimulator.test_multiple_heights_and_signed_certificates
# T2: TestConsensusIntegration + TV3 transport tests (no saved vote-pool trace)
# T3: TV2 crypto + TestNode (missing explicit TX-signature-as-VOTE attack)
# T4: TestNode (missing replay after commit and duplicate TX inside a block)
# T5: TestBlockchainSimulator.test_loss_duplication_reordering_and_stabilization
# T6: silent/crashed proposer tests (missing saved leader/round transition trace)
# T7: test_consensus checks one engine; no distributed f-Byzantine scenario.
# The acceptance tests below preserve evidence in outputs/tv4_evidence/*.json.


@pytest.fixture
def acceptance_evidence(request):
    """Save real node/network logs separately from test-observer measurements.

    No synthetic duplicate/replay/equivocation event is presented as a node
    log. These measurements are explicitly labeled source='test_observer'.
    Evidence is written during teardown, including after an assertion fails.
    """
    cases = {}

    def record(test_id, sim, **measurements):
        if test_id not in cases:
            cases[test_id] = (sim, {})
        cases[test_id][1].update(measurements)

    yield record
    folder = Path(__file__).resolve().parents[1] / "outputs" / "tv4_evidence"
    folder.mkdir(parents=True, exist_ok=True)
    name = re.sub(r"[^A-Za-z0-9_-]+", "_", request.node.name)
    for test_id, (sim, measurements) in cases.items():
        evidence = {
            "test_id": test_id, "pytest_nodeid": request.node.nodeid,
            "seed": sim.config.seed, "validators": sim.node_ids,
            "validator_public_keys": sim.public_keys,
            "correct_nodes": sim.correct_nodes, "faulty_nodes": sorted(sim.faulty_nodes),
            "network_config": sim.network.config.to_dict(),
            "simulation_time": sim.scheduler.now,
            "finalized_block_hashes": {
                name: {str(h): block.block_id for h, block in node.chain.items()}
                for name, node in sim.nodes.items()
            },
            "state_hashes": {name: node.world_state.state_root() for name, node in sim.nodes.items()},
            "states": {name: node.world_state.to_dict() for name, node in sim.nodes.items()},
            "node_and_network_log": sim.log,
            "test_observer": measurements,
        }
        (folder / f"{test_id}_{name}.json").write_text(
            json.dumps(evidence, indent=2, sort_keys=True), encoding="utf-8",
        )


def observe_vote_guards(sim, monkeypatch):
    """Measure the actual VoteGuard result and pool, without changing its result."""
    trace = []
    for name, node in sim.nodes.items():
        guard = node.engine.votes
        original_add = guard.add

        def add(vote, *, name=name, guard=guard, original_add=original_add):
            previous = next((v for v in guard.votes(vote.height, vote.round, vote.phase)
                             if v.voter_id == vote.voter_id), None)
            accepted = original_add(vote)
            event = "vote_stored" if accepted else "vote_rejected"
            if not accepted and previous is not None:
                event = "equivocation" if previous.block_id != vote.block_id else "duplicate_ignored"
            pool = [{"voter_id": v.voter_id, "block_id": v.block_id}
                    for v in guard.votes(vote.height, vote.round, vote.phase)]
            trace.append({
                "source": "test_observer", "event": event, "time": sim.scheduler.now,
                "node_id": name, "vote": vote.to_dict(), "accepted": accepted,
                "previous_vote": previous.to_dict() if previous else None,
                "vote_pool": pool,
            })
            return accepted

        monkeypatch.setattr(guard, "add", add)
    return trace


def observe_finalizations(sim, monkeypatch):
    """Check safety at every COMMIT, rather than only at the final snapshot."""
    trace, committed = [], {}
    for name in sim.correct_nodes:
        node = sim.nodes[name]
        original_log = node._log

        def log(event, *, name=name, original_log=original_log, **details):
            original_log(event, **details)
            if event == "COMMIT":
                key = (name, details["height"])
                assert key not in committed, "a correct node committed the same height twice"
                committed[key] = details["block_id"]
                values = {bid for (peer, height), bid in committed.items() if height == details["height"]}
                assert len(values) == 1, "correct nodes finalized conflicting blocks"
                trace.append({"source": "test_observer", "time": sim.scheduler.now,
                              "node_id": name, **details})
                sim.assert_invariants()

        monkeypatch.setattr(node, "_log", log)
    return trace


def assert_unique_vote_pools(trace):
    for item in trace:
        voters = [vote["voter_id"] for vote in item["vote_pool"]]
        assert len(voters) == len(set(voters)), "one validator was counted more than once"


def assert_common_chain(sim, target):
    chains = [tuple(sim.nodes[name].chain[h].block_id for h in range(1, target + 1))
              for name in sim.correct_nodes]
    assert len(set(chains)) == 1
    for h in range(1, target + 1):
        assert len({sim.nodes[name].chain[h].state_root for name in sim.correct_nodes}) == 1
    sim.assert_invariants()


class TestAcceptanceRequirements:
    @pytest.mark.parametrize("size", [8, 10])
    def test_t1_normal_run_chain_and_state_hashes(self, size, monkeypatch, acceptance_evidence):
        sim = make_simulator(size)
        commits = observe_finalizations(sim, monkeypatch)
        acceptance_evidence("T1", sim, finalization_observations=commits)
        tx = sim.make_transaction("node_1", "node_2", 37, 0)
        sim.submit_transaction(tx)
        result = sim.run(3)
        acceptance_evidence("T1", sim, finalization_observations=commits,
                            completed=result.completed, stop_reason=result.stop_reason)
        assert result.completed and len(sim.nodes) >= 8
        assert sim.network.config.drop_rate == sim.network.config.duplicate_rate == 0
        assert result.network_counters["dropped"] == 0
        assert_common_chain(sim, 3)
        assert len(set(result.state_roots_by_node.values())) == 1
        assert all(node.world_state.get_balance(tx.sender) == 963 for node in sim.nodes.values())
        assert all(node.world_state.get_nonce(tx.sender) == 1 for node in sim.nodes.values())
        assert len(commits) >= 3 * size

    def test_t2_duplicate_reordered_votes_count_once(self, monkeypatch, acceptance_evidence):
        sim = make_simulator(8, network=NetworkConfig(
            min_delay=0.001, max_delay=0.03, duplicate_rate=1.0,
        ))
        votes = observe_vote_guards(sim, monkeypatch)
        commits = observe_finalizations(sim, monkeypatch)
        acceptance_evidence("T2", sim, vote_guard_observations=votes, finalization_observations=commits)
        result = sim.run(2)
        order = {}
        for event in sim.network.events:
            if event.event == "DELIVER" and event.kind in ("PREVOTE", "PRECOMMIT"):
                order.setdefault((event.node_id, event.peer_id), []).append(
                    int(event.envelope_id.split("-")[1])
                )
        inversions = [{"sender": link[0], "recipient": link[1], "envelope_sequence": sequence}
                      for link, sequence in order.items()
                      if any(a > b for a, b in zip(sequence, sequence[1:]))]
        acceptance_evidence("T2", sim, vote_guard_observations=votes,
                            reordered_deliveries=inversions, finalization_observations=commits)
        assert result.completed and result.network_counters["duplicates_created"] > 0
        assert inversions, "the test must actually reorder vote packets"
        assert any(item["event"] == "duplicate_ignored" for item in votes)
        assert_unique_vote_pools(votes)
        assert all(verify_vote_signature(Vote.from_dict(item["vote"]),
                                        sim.public_keys[item["vote"]["voter_id"]]) for item in votes)
        assert_common_chain(sim, 2)

    @pytest.mark.parametrize("phase", [Phase.PREVOTE, Phase.PRECOMMIT], ids=["prevote", "precommit"])
    @pytest.mark.parametrize("attack", ["tampered_payload", "tx_signature", "other_phase_signature"])
    def test_t3_invalid_signature_and_wrong_domain(self, attack, phase, acceptance_evidence):
        sim = make_simulator()
        leader = sim.selector.proposer_for(1, 0)
        target_id = next(name for name in sim.node_ids if name != leader)
        sender = next(name for name in sim.node_ids if name != target_id)
        node = sim.nodes[target_id]
        block = empty_block(sim)
        assert node.engine.accept_proposal(block)
        node.blocks[block.block_id] = block
        valid = signed_vote(sim, sender, phase, block.block_id)
        if attack == "tampered_payload":
            invalid = replace(valid, block_id="payload-changed-after-signing")
        elif attack == "tx_signature":
            tx = sim.make_transaction(sender, target_id, 1, 0)
            invalid = replace(valid, signature=tx.signature)
        else:
            other = Phase.PRECOMMIT if phase == Phase.PREVOTE else Phase.PREVOTE
            invalid = replace(valid, signature=signed_vote(sim, sender, other, block.block_id).signature)
        before = node.world_state.to_dict()
        acceptance_evidence("T3", sim, attack=attack, invalid_vote=invalid.to_dict(), state_before=before)
        assert not verify_vote_signature(invalid, sim.public_keys[sender])
        node.start()  # Only this non-proposer is active: isolate the rejection.
        sim.network.send(sender, target_id, invalid.to_dict(), kind=phase.value, height=1)
        sim.scheduler.run_until(0.04)
        sim.stop()
        failures = [event for event in node.events if event["event"] == "REJECT_MESSAGE"]
        acceptance_evidence("T3", sim, attack=attack, invalid_vote=invalid.to_dict(),
                            rejection_log=failures, state_before=before, state_after=node.world_state.to_dict())
        assert failures and "signature" in failures[-1]["reason"]
        assert node.engine.votes.count(1, 0, phase, invalid.block_id) == 0
        assert node.committed_height == 0 and node.world_state.to_dict() == before

    def test_t4_replay_before_and_after_commit(self, acceptance_evidence):
        sim = make_simulator()
        tx = sim.make_transaction("node_1", "node_2", 41, 0)
        before = {name: node.world_state.to_dict() for name, node in sim.nodes.items()}
        acceptance_evidence("T4", sim, source="test_observer", tx=tx.to_dict(), state_before=before)
        assert all(sim.submit_transaction(tx).values())
        duplicate_admission = sim.submit_transaction(tx)
        assert not any(duplicate_admission.values())
        assert sim.run(1).completed
        after_first = {name: node.world_state.to_dict() for name, node in sim.nodes.items()}
        replay_admission = sim.submit_transaction(tx)
        replay_validation = {
            name: validate_transaction(tx, node.world_state.copy()).error
            for name, node in sim.nodes.items()
        }
        result = sim.run(3)
        acceptance_evidence("T4", sim, source="test_observer", tx=tx.to_dict(),
                            state_before=before, state_after_first_commit=after_first,
                            duplicate_admission=duplicate_admission, replay_admission=replay_admission,
                            replay_validation_errors=replay_validation)
        assert result.completed
        assert all("nonce" in reason for reason in replay_validation.values())
        for name, node in sim.nodes.items():
            assert node.world_state.to_dict() == after_first[name]
            assert node.world_state.get_balance(tx.sender) == 959
            assert node.world_state.get_nonce(tx.sender) == 1
            assert sum(item == tx for block in node.chain.values() for item in block.transactions) == 1
        assert_common_chain(sim, 3)

    def test_t4_duplicate_signed_transaction_inside_block(self, monkeypatch, acceptance_evidence):
        sim = make_simulator()
        tx = sim.make_transaction("node_1", "node_2", 13, 0)
        sim.submit_transaction(tx)
        proposer = sim.nodes[sim.selector.proposer_for(1, 0)]
        state = proposer.world_state.copy()
        assert apply_transaction(tx, state).success
        bad = sign_block(replace(empty_block(sim), transactions=(tx, tx), state_root=state.state_root()),
                         proposer.private_key)
        validation = validate_block(bad, proposer.world_state, proposer.engine.parent_id,
                                    proposer_public_key=sim.public_keys[proposer.node_id], require_state_root=True)
        acceptance_evidence("T4", sim, source="test_observer", duplicate_block=bad.to_dict(),
                            validation_error=validation.error)
        original = proposer.propose_block

        def propose_duplicate():
            if (proposer.engine.height, proposer.engine.round) != (1, 0):
                return original()
            header = proposer._make_header("PROPOSAL", bad, 0)
            proposer._announce(header, bad)
            proposer._handle_proposal(header, bad)
            return bad

        monkeypatch.setattr(proposer, "propose_block", propose_duplicate)
        result = sim.run(2)
        acceptance_evidence("T4", sim, source="test_observer", duplicate_block=bad.to_dict(),
                            validation_error=validation.error)
        assert not validation.valid and "tx[1]" in validation.error and "nonce" in validation.error
        assert result.completed
        assert all(node.chain[1].block_id != bad.block_id for node in sim.nodes.values())
        assert any(event["event"] == "REJECT_PROPOSAL" for event in sim.log)
        for node in sim.nodes.values():
            assert node.world_state.get_balance(tx.sender) == 987
            assert node.world_state.get_nonce(tx.sender) == 1

    @pytest.mark.parametrize("seed", [7, 23])
    def test_t5_safety_before_and_after_synchrony(self, seed, monkeypatch, acceptance_evidence):
        stable_at = 0.4
        sim = make_simulator(8, seed, network=NetworkConfig(
            min_delay=0.001, max_delay=0.02, pre_synchrony_max_delay=0.15,
            drop_rate=0.4, duplicate_rate=0.5, stabilize_at=stable_at,
        ))
        commits = observe_finalizations(sim, monkeypatch)
        acceptance_evidence("T5", sim, stabilize_at=stable_at, finalization_observations=commits)
        sim.start()
        sim.scheduler.run_until(stable_at - 0.001)
        heights_before = {name: node.committed_height for name, node in sim.nodes.items()}
        sim.assert_invariants()
        target = max(heights_before.values()) + 3
        result = sim.run(target, max_simulation_time=10)
        before_drops = [event.to_dict() for event in sim.network.events
                        if event.event == "DROP" and event.time < stable_at and event.reason == "random_drop"]
        after_sends = [event.to_dict() for event in sim.network.events
                       if event.event == "SEND" and event.time >= stable_at]
        delayed_before = [event.to_dict() for event in sim.network.events
                          if event.event == "SEND" and event.time < stable_at
                          and event.delay > sim.network.config.max_delay]
        acceptance_evidence("T5", sim, stabilize_at=stable_at, heights_before_synchrony=heights_before,
                            pre_synchrony_drops=before_drops, pre_synchrony_delays=delayed_before,
                            post_synchrony_sends=after_sends,
                            finalization_observations=commits)
        assert before_drops and delayed_before
        assert result.completed and after_sends
        assert all(event["delay"] <= sim.network.config.max_delay for event in after_sends)
        assert not any(event.event == "DROP" and event.time >= stable_at and event.reason == "random_drop"
                       for event in sim.network.events)
        assert any(item["time"] >= stable_at for item in commits)
        assert_common_chain(sim, target)

    @pytest.mark.parametrize("fault", ["silent", "crashed"])
    def test_t6_timeout_round_change_and_next_proposer(self, fault, acceptance_evidence):
        sim = make_simulator(8)
        first = sim.selector.proposer_for(1, 0)
        next_leader = sim.selector.proposer_for(1, 1)
        acceptance_evidence("T6", sim, fault=fault, first_proposer=first, next_proposer=next_leader)
        if fault == "silent":
            sim.nodes[first].silent_proposer = True
        else:
            sim.schedule_crash(first, 0)
        result = sim.run(2)
        timeouts = [event for event in sim.log if event["event"] == "TIMEOUT" and event["expired_height"] == 1]
        proposals = [event for event in sim.log if event["event"] == "PROPOSE" and event["height"] == 1]
        acceptance_evidence("T6", sim, fault=fault, first_proposer=first, next_proposer=next_leader,
                            timeout_log=timeouts, proposal_log=proposals)
        assert result.completed and timeouts
        assert any(event["expired_round"] == 0 and event["round"] == 1 for event in timeouts)
        assert not any(event["round"] == 0 for event in proposals)
        assert any(event["round"] == 1 and event["node_id"] == next_leader for event in proposals)
        assert all(sim.nodes[name].certificates[1].round == 1 for name in sim.correct_nodes)
        assert_common_chain(sim, 2)

    @pytest.mark.parametrize("f", [1, 2, 3])
    def test_t7_up_to_f_byzantine_equivocators(self, f, monkeypatch, acceptance_evidence):
        """Use real signed conflicting votes and two valid equivocated proposals.

        Faulty validator handlers are replaced by an explicit network attacker.
        Correct-node code and transport are unchanged. Different peer groups
        see different first votes; subsequent contradictory votes include nil
        so VoteGuard also records conflicts for candidates it already knows.
        """
        sim = make_simulator(3 * f + 1)
        leader = sim.selector.proposer_for(1, 0)
        others = [name for name in sim.node_ids if name != leader]
        byzantine = [leader] + others[:f - 1]
        sim.faulty_nodes.update(byzantine)
        honest = sim.correct_nodes
        assert len(byzantine) == f and len(sim.node_ids) == 3 * f + 1
        votes = observe_vote_guards(sim, monkeypatch)
        commits = observe_finalizations(sim, monkeypatch)
        proposals = [empty_block(sim)]
        proposals.append(sign_block(replace(proposals[0], timestamp=0.000001), sim.nodes[leader].private_key))
        injections, deliveries = [], []
        acceptance_evidence("T7", sim, f=f, conflicting_proposals=[b.to_dict() for b in proposals],
                            injected_votes=injections, delivered_votes=deliveries,
                            vote_guard_observations=votes, finalization_observations=commits)
        for name in byzantine:
            monkeypatch.setattr(sim.nodes[name], "start", lambda: None)

        def serve_byzantine_body(node_id, envelope):
            if envelope.kind == KIND_BODY_REQUEST:
                entry = sim.nodes[leader]._outgoing.get(envelope.header_id)
                if entry:
                    header, block = entry
                    sim.network.send_body(leader, envelope.sender_id, envelope.header_id,
                                          {"block": block.to_dict()}, height=header["height"])

        sim.network.set_receiver(leader, serve_byzantine_body)
        for name in honest:
            original = sim.nodes[name].on_receive

            def receive(node_id, envelope, *, original=original):
                if envelope.sender_id in byzantine and envelope.kind in ("PREVOTE", "PRECOMMIT"):
                    deliveries.append({"source": "test_observer", "time": sim.scheduler.now,
                                       "sender": envelope.sender_id, "recipient": node_id,
                                       "vote": dict(envelope.payload)})
                original(node_id, envelope)

            sim.network.set_receiver(name, receive)

        def attack():
            for index, peer in enumerate(honest):
                preferred = proposals[index % 2]
                header = sim.nodes[leader]._make_header("PROPOSAL", preferred, 0)
                sim.nodes[leader]._announce(header, preferred, [peer])
                choices = [preferred.block_id, proposals[1 - index % 2].block_id, NIL_BLOCK_ID]
                for sender in byzantine:
                    for phase in (Phase.PREVOTE, Phase.PRECOMMIT):
                        for order, block_id in enumerate(choices):
                            vote = signed_vote(sim, sender, phase, block_id)
                            injections.append({"source": "test_observer", "sender": sender,
                                               "recipient": peer, "order": order, "vote": vote.to_dict()})
                            # Deliver contradictory PREVOTEs before Byzantine
                            # PRECOMMITs can finish height 1. Otherwise a fast
                            # finalize would legitimately discard old conflicts.
                            phase_start = 0.04 if phase == Phase.PREVOTE else 0.12
                            sim.scheduler.schedule_after(
                                phase_start + order * 0.015, sim.network.send, sender, peer, vote.to_dict(),
                                kind=phase.value, height=1, tag="byzantine-equivocation",
                            )

        sim.scheduler.schedule_at(0, attack, tag="byzantine-proposals")
        result = sim.run(2, max_simulation_time=15)
        conflicts = [item for item in votes if item["event"] == "equivocation" and item["node_id"] in honest]
        acceptance_evidence("T7", sim, f=f, conflicting_proposals=[b.to_dict() for b in proposals],
                            injected_votes=injections, delivered_votes=deliveries,
                            vote_guard_observations=votes, equivocation_observations=conflicts,
                            finalization_observations=commits)
        assert result.completed, "correct nodes must continue despite f equivocating validators"
        assert proposals[0].block_id != proposals[1].block_id
        assert conflicts, "the attack must exercise actual VoteGuard conflict handling"
        for sender in byzantine:
            observed = [item for item in deliveries if item["sender"] == sender]
            assert {item["vote"]["block_id"] for item in observed} >= {b.block_id for b in proposals}
            assert all(verify_vote_signature(Vote.from_dict(item["vote"]), sim.public_keys[sender]) for item in observed)
            first_choices = {}
            for item in observed:
                if item["vote"]["phase"] == "PREVOTE":
                    first_choices.setdefault(item["recipient"], item["vote"]["block_id"])
            assert len(set(first_choices.values())) == 2
        assert_unique_vote_pools(votes)
        assert_common_chain(sim, 2)


# %% Run all cells as a regular script, or use pytest directly.
if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
