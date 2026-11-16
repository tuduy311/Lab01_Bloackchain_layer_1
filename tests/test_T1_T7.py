# %% [markdown]
# Assignment acceptance scenarios T1--T7 and their saved evidence.
# Run: python -m pytest tests/test_T1_T7.py -v
# Evidence: outputs/tv4_evidence/; audit: python scripts/audit_tv4_evidence.py

"""T1--T7 acceptance tests with genuine signatures and evidence collection."""

import ast
import hashlib
import json
import re
import sys
import textwrap
from collections import Counter
from dataclasses import replace
from inspect import getsourcelines
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.crypto import sha256_hex, sign_block, verify_vote_signature
from src.execution import apply_transaction, validate_transaction
from src.models import NIL_BLOCK_ID, Phase, Vote, _canonical_json
from src.network import KIND_BODY_REQUEST, NetworkConfig
from tests.simulation_helpers import empty_block, make_simulator, signed_vote


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
    project = Path(__file__).resolve().parents[1]
    folder = project / "outputs" / "tv4_evidence"
    folder.mkdir(parents=True, exist_ok=True)
    name = re.sub(r"[^A-Za-z0-9_-]+", "_", request.node.name)
    source_lines, source_start = getsourcelines(request.function)
    test_source = textwrap.dedent("".join(source_lines))
    assertions = [
        {"file": Path(request.node.path).relative_to(project).as_posix(), "line": source_start + item.lineno - 1,
         "expression": ast.get_source_segment(test_source, item.test)}
        for item in ast.walk(ast.parse(test_source)) if isinstance(item, ast.Assert)
    ]
    report = getattr(request.node, "_tv4_reports", {}).get("call")
    pytest_result = {
        "source": "pytest", "nodeid": request.node.nodeid,
        "outcome": report.outcome if report is not None else "not_run",
        "duration_seconds": report.duration if report is not None else None,
        "failure": str(report.longrepr) if report is not None and report.failed else None,
        "assertion_definitions": assertions,
        "assertion_note": "Static test assertions; outcome is pytest's actual result for the whole test.",
    }
    fingerprint = hashlib.sha256()
    for source_file in sorted([*project.joinpath("src").rglob("*.py"),
                               *project.joinpath("tests").rglob("*.py")]):
        fingerprint.update(source_file.relative_to(project).as_posix().encode("utf-8") + b"\0")
        fingerprint.update(source_file.read_bytes())
    for test_id, (sim, measurements) in cases.items():
        evidence = {
            "test_id": test_id, "pytest_nodeid": request.node.nodeid,
            "pytest_result": pytest_result,
            "source_fingerprint_sha256": fingerprint.hexdigest(),
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
            "consensus_log": [event for event in sim.log if event["source"] == "node"],
            "network_event_log": [event for event in sim.log if event["source"] == "network"],
            "test_observer": measurements,
        }
        (folder / f"{test_id}_{name}.json").write_text(
            json.dumps(evidence, indent=2, sort_keys=True), encoding="utf-8",
        )


def observe_vote_pools(sim, monkeypatch):
    """Measure the actual VotePool result and pool, without changing its result."""
    trace = []
    for name, node in sim.nodes.items():
        pool = node.engine.vote_pool
        original_add = pool.add_vote

        def add(vote, *, name=name, pool=pool, original_add=original_add):
            previous = next((v for v in pool.get_round_votes(vote.height, vote.round, vote.phase)
                             if v.voter_id == vote.voter_id), None)
            accepted = original_add(vote)
            event = "vote_stored" if accepted else "vote_rejected"
            if not accepted and previous is not None:
                event = "equivocation" if previous.block_id != vote.block_id else "duplicate_ignored"
            pool_snapshot = [{"voter_id": v.voter_id, "block_id": v.block_id}
                             for v in pool.get_round_votes(vote.height, vote.round, vote.phase)]
            trace.append({
                "source": "test_observer", "event": event, "time": sim.scheduler.now,
                "node_id": name, "vote": vote.to_dict(), "accepted": accepted,
                "previous_vote": previous.to_dict() if previous else None,
                "vote_pool": pool_snapshot,
                "vote_counts_by_validator": dict(Counter(v["voter_id"] for v in pool_snapshot)),
                "vote_counts_by_block": dict(Counter(v["block_id"] for v in pool_snapshot)),
            })
            return accepted

        monkeypatch.setattr(pool, "add_vote", add)
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
        votes = observe_vote_pools(sim, monkeypatch)
        commits = observe_finalizations(sim, monkeypatch)
        acceptance_evidence("T2", sim, vote_pool_observations=votes, finalization_observations=commits)
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
        acceptance_evidence("T2", sim, vote_pool_observations=votes,
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
        assertion_evidence = {
            "signature_valid": verify_vote_signature(invalid, sim.public_keys[sender]),
            "rejection_logged": bool(failures),
            "rejection_reason": failures[-1]["reason"] if failures else None,
            "counted_votes": len(node.engine.vote_pool.get_votes(1, 0, phase, invalid.block_id)),
            "committed_height": node.committed_height,
            "state_unchanged": node.world_state.to_dict() == before,
        }
        acceptance_evidence("T3", sim, attack=attack, invalid_vote=invalid.to_dict(),
                            rejection_log=failures, state_before=before, state_after=node.world_state.to_dict(),
                            assertion_evidence=assertion_evidence)
        assert failures and "signature" in failures[-1]["reason"]
        assert len(node.engine.vote_pool.get_votes(1, 0, phase, invalid.block_id)) == 0
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
        replay_time = sim.scheduler.now
        replay_admission = sim.submit_transaction(tx)
        replay_validation = {
            name: validate_transaction(tx, node.world_state.copy()).error
            for name, node in sim.nodes.items()
        }
        result = sim.run(3)
        tx_id = sha256_hex(_canonical_json(tx.to_dict()))
        replay_log = [
            {"source": "test_observer", "event": "duplicate_transaction_ignored", "time": 0.0,
             "node_id": name, "tx_id": tx_id, "admitted": admitted}
            for name, admitted in duplicate_admission.items()
        ] + [
            {"source": "test_observer", "event": "replayed_transaction_not_executable", "time": replay_time,
             "node_id": name, "tx_id": tx_id, "admitted_to_mempool": replay_admission[name], "reason": reason}
            for name, reason in replay_validation.items()
        ]
        applied_counts = {name: sum(item == tx for block in node.chain.values() for item in block.transactions)
                          for name, node in sim.nodes.items()}
        acceptance_evidence("T4", sim, source="test_observer", tx=tx.to_dict(),
                            state_before=before, state_after_first_commit=after_first,
                            state_after={name: node.world_state.to_dict() for name, node in sim.nodes.items()},
                            duplicate_admission=duplicate_admission, replay_admission=replay_admission,
                            replay_validation_errors=replay_validation,
                            replay_duplicate_log=replay_log, transaction_applied_count=applied_counts)
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
        before = {name: node.world_state.to_dict() for name, node in sim.nodes.items()}
        proposer = sim.nodes[sim.selector.proposer_for(1, 0)]
        state = proposer.world_state.copy()
        assert apply_transaction(tx, state).success
        bad = sign_block(replace(empty_block(sim), transactions=(tx, tx), state_root=state.state_root()),
                         proposer.private_key)
        assert proposer.block_validator.validate(bad, proposer.chain[proposer.committed_height]) is False
        validation = proposer.block_validator.last_result
        acceptance_evidence("T4", sim, source="test_observer", duplicate_block=bad.to_dict(),
                            validation_error=validation.error, state_before=before)
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
                            validation_error=validation.error, state_before=before,
                            state_after={name: node.world_state.to_dict() for name, node in sim.nodes.items()},
                            transaction_applied_count={
                                name: sum(item == tx for block in node.chain.values() for item in block.transactions)
                                for name, node in sim.nodes.items()
                            },
                            replay_duplicate_log=[{
                                "source": "test_observer", "event": "duplicate_transaction_block_rejected",
                                "time": 0.0, "node_id": proposer.node_id,
                                "tx_id": sha256_hex(_canonical_json(tx.to_dict())), "block_id": bad.block_id,
                                "occurrences_in_proposed_block": 2, "reason": validation.error,
                            }])
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
        round_changes = [event for event in sim.log if event["event"] == "ENTER_ROUND"
                         and event["height"] == 1 and event["round"] > 0]
        acceptance_evidence("T6", sim, fault=fault, first_proposer=first, next_proposer=next_leader,
                            timeout_log=timeouts, proposal_log=proposals, round_change_log=round_changes)
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
        so VotePool also records conflicts for candidates it already knows.
        """
        sim = make_simulator(3 * f + 1)
        leader = sim.selector.proposer_for(1, 0)
        others = [name for name in sim.node_ids if name != leader]
        byzantine = [leader] + others[:f - 1]
        sim.faulty_nodes.update(byzantine)
        honest = sim.correct_nodes
        assert len(byzantine) == f and len(sim.node_ids) == 3 * f + 1
        votes = observe_vote_pools(sim, monkeypatch)
        commits = observe_finalizations(sim, monkeypatch)
        proposals = [empty_block(sim)]
        proposals.append(sign_block(replace(proposals[0], timestamp=0.000001), sim.nodes[leader].private_key))
        injections, deliveries = [], []
        acceptance_evidence("T7", sim, f=f, conflicting_proposals=[b.to_dict() for b in proposals],
                            injected_votes=injections, delivered_votes=deliveries,
                            vote_pool_observations=votes, finalization_observations=commits)
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
                            vote_pool_observations=votes, equivocation_observations=conflicts,
                            finalization_observations=commits)
        assert result.completed, "correct nodes must continue despite f equivocating validators"
        assert proposals[0].block_id != proposals[1].block_id
        assert conflicts, "the attack must exercise actual VotePool conflict handling"
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
