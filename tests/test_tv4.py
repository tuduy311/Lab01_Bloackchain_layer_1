# %% [markdown]
# TV4: integration, regression and required public API tests.
# Run: python -m pytest tests/test_tv4.py -v
# Assignment acceptance scenarios T1--T7 are in tests/test_T1_T7.py.

"""Integration tests with real Ed25519 signatures and independent node states."""

import json
import sys
from dataclasses import replace
from inspect import signature
from pathlib import Path
from typing import get_type_hints

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.blockchain_simulator import BlockchainSimulator, SimulationConfig
from src.consensus.locking import Polka, VotePool
from src.crypto import ValidatorKeyStore, compute_block_id, sign_block, verify_vote_signature
from src.execution import BlockValidator
from src.models import Block, FinalizeCertificate, NIL_BLOCK_ID, Phase, ValidatorSet, Vote
from src.network import NetworkConfig, NetworkEnvelope, SendStatus
from src.scheduler import Scheduler
from tests.simulation_helpers import certificate, empty_block, make_simulator, signed_vote


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
        assert not node.engine.vote_pool.get_round_votes(1, 0, Phase.PREVOTE)
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
        assert len(engine.vote_pool.get_votes(1, 0, Phase.PREVOTE, "another")) == 0

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


# %% Required public API contracts and integration after the direct refactor
class TestRequiredPublicAPIs:
    def test_required_signatures_and_types(self):
        assert list(signature(VotePool.add_vote).parameters) == ["self", "vote"]
        for method in (VotePool.has_quorum, VotePool.get_votes):
            assert list(signature(method).parameters) == ["self", "height", "round", "phase", "block_id"]
        assert get_type_hints(VotePool.add_vote)["return"] is bool
        assert get_type_hints(VotePool.has_quorum)["return"] is bool
        assert get_type_hints(VotePool.get_votes)["return"] == list[Vote]
        assert list(signature(BlockValidator.validate).parameters) == ["self", "block", "parent"]
        assert get_type_hints(BlockValidator.validate)["return"] is bool
        assert get_type_hints(Block)["block_id"] is str
        block = empty_block(make_simulator())
        assert type(block.block_id) is str and block.block_id == compute_block_id(block)

    def test_get_votes_returns_an_independent_sorted_list(self):
        pool = VotePool(("a", "b", "c", "d"))
        for voter in ("c", "a", "b"):
            assert pool.add_vote(Vote(1, 0, Phase.PREVOTE, "A", voter)) is True
        result = pool.get_votes(1, 0, Phase.PREVOTE, "A")
        assert type(result) is list
        assert [vote.voter_id for vote in result] == ["a", "b", "c"]
        result.clear()
        assert pool.has_quorum(1, 0, Phase.PREVOTE, "A") is True
        assert len(pool.get_votes(1, 0, Phase.PREVOTE, "A")) == 3

    def test_vote_pool_separates_each_slot_and_block(self):
        pool = VotePool(("a", "b", "c", "d"))
        for voter in ("a", "b", "c"):
            assert pool.add_vote(Vote(1, 0, Phase.PREVOTE, "A", voter))
        for height, round_, phase, block_id, voter in (
            (2, 0, Phase.PREVOTE, "A", "a"),
            (1, 1, Phase.PREVOTE, "A", "a"),
            (1, 0, Phase.PRECOMMIT, "A", "a"),
            (1, 0, Phase.PREVOTE, "B", "d"),
        ):
            assert pool.add_vote(Vote(height, round_, phase, block_id, voter))
            assert len(pool.get_votes(height, round_, phase, block_id)) == 1
            assert pool.has_quorum(height, round_, phase, block_id) is False
        assert pool.has_quorum(1, 0, Phase.PREVOTE, "A") is True

    @pytest.mark.parametrize("phase", [Phase.PREVOTE, Phase.PRECOMMIT])
    def test_vote_pool_deduplicates_conflicts_and_nil(self, phase):
        pool = VotePool(("a", "b", "c", "d"))
        first = Vote(1, 0, phase, "A", "a")
        assert pool.add_vote(first) is True
        assert pool.add_vote(first) is False
        assert pool.add_vote(replace(first, block_id="B")) is False
        assert pool.add_vote(replace(first, voter_id="outsider")) is False
        assert pool.conflicts == [(first, replace(first, block_id="B"))]
        assert pool.get_votes(1, 0, phase, "B") == []
        for voter in ("b", "c"):
            assert pool.add_vote(Vote(1, 0, phase, NIL_BLOCK_ID, voter))
        assert pool.has_quorum(1, 0, phase, NIL_BLOCK_ID) is False
        assert pool.add_vote(Vote(1, 0, phase, NIL_BLOCK_ID, "d"))
        assert pool.has_quorum(1, 0, phase, NIL_BLOCK_ID) is True
        assert pool.has_quorum(1, 0, phase, "A") is False

    @pytest.mark.parametrize("size,quorum", [(1, 1), (4, 3), (7, 5), (8, 6), (10, 7)])
    def test_vote_pool_quorum_boundary(self, size, quorum):
        ids = tuple(f"v{i}" for i in range(size))
        pool = VotePool(ids)
        assert pool.quorum == quorum
        for voter in ids[:quorum - 1]:
            assert pool.add_vote(Vote(1, 0, Phase.PREVOTE, "A", voter))
        assert pool.has_quorum(1, 0, Phase.PREVOTE, "A") is False
        assert pool.add_vote(Vote(1, 0, Phase.PREVOTE, "A", ids[quorum - 1]))
        assert pool.has_quorum(1, 0, Phase.PREVOTE, "A") is True

    def test_node_and_engine_use_validator_with_live_committed_state(self, monkeypatch):
        sim = make_simulator()
        node = sim.nodes["node_1"]
        validator = node.block_validator
        assert isinstance(validator, BlockValidator)
        assert node.engine.block_validator is validator
        assert isinstance(node.engine.vote_pool, VotePool)
        assert node.engine.parent_block is node.chain[0]
        initial_state = node.world_state
        calls = []
        original = validator.validate

        def validate(block, parent):
            result = original(block, parent)
            calls.append((block.height, parent.height, parent.block_id, result))
            assert type(result) is bool
            return result

        monkeypatch.setattr(validator, "validate", validate)
        tx = sim.make_transaction("node_1", "node_2", 19, 0)
        sim.submit_transaction(tx)
        assert sim.run(3).completed
        assert node.world_state is not initial_state
        assert initial_state.get_balance(tx.sender) == 1000
        assert node.world_state.get_balance(tx.sender) == 981
        assert node.engine.parent_block is node.chain[node.committed_height]
        assert {height for height, _, _, valid in calls if valid} >= {1, 2, 3}
        assert all(height == parent_height + 1 for height, parent_height, _, _ in calls)

    @pytest.mark.parametrize("case", ["wrong_id", "wrong_height", "missing_parent", "wrong_parent_state"])
    def test_block_validator_checks_parent_argument(self, case):
        sim = make_simulator()
        node = sim.nodes["node_1"]
        parent, block = node.chain[0], empty_block(sim)
        before = node.world_state.to_dict()
        if case == "wrong_id":
            parent = replace(parent, block_id="wrong-parent")
        elif case == "wrong_height":
            parent = replace(parent, height=1)
        elif case == "missing_parent":
            parent = None
        else:
            parent = replace(parent, state_root="wrong-pre-state-root")
        assert node.block_validator.validate(block, parent) is False
        assert node.block_validator.last_result.error
        assert node.world_state.to_dict() == before

    def test_block_validator_requires_root_in_node_configuration(self):
        sim = make_simulator()
        node = sim.nodes["node_1"]
        block = empty_block(sim)
        block = sign_block(replace(block, state_root=""), sim.key_store.private_key(block.proposer_id))
        assert node.block_validator.validate(block, node.chain[0]) is False
        assert node.block_validator.last_result.error == "missing state_root"
        assert node.engine.accept_proposal(block) is False

    def test_block_validator_does_not_commit_valid_prefix_of_invalid_block(self):
        sim = make_simulator()
        node = sim.nodes["node_1"]
        tx1 = sim.make_transaction("node_1", "node_2", 10, 0)
        tx2 = sim.make_transaction("node_1", "node_2", 10000, 1)
        template = empty_block(sim)
        invalid = sign_block(replace(template, transactions=(tx1, tx2)),
                             sim.key_store.private_key(template.proposer_id))
        before = node.world_state.to_dict()
        assert node.block_validator.validate(invalid, node.chain[0]) is False
        assert "tx[1]" in node.block_validator.last_result.error
        assert node.world_state.to_dict() == before
        assert node.block_validator.validate(template, node.chain[0]) is True
        assert node.block_validator.last_result.error == ""


# %% Run all cells as a regular script, or use pytest directly.
if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
