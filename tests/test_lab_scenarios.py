"""End-to-end acceptance scenarios from Lab 01 (T1 through T8)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.blockchain_simulator import BlockchainSimulator
from src.crypto import sign_vote
from src.models import Phase, Vote
from scripts.deterministic_check import check_determinism


def _config(name: str) -> dict:
    with (ROOT / "scenarios" / name).open("r", encoding="utf-8") as stream:
        return json.load(stream)


def _run(name: str):
    simulator = BlockchainSimulator(_config(name))
    return simulator, simulator.run()


def test_t1_normal_run_converges_with_matching_state_hashes():
    simulator, result = _run("T1_normal.json")
    assert result.converged
    assert result.safety_holds
    assert len(set(result.ledgers.values())) == 1
    alice = simulator.participant_public_keys["alice"]
    bob = simulator.participant_public_keys["bob"]
    for node in simulator.nodes.values():
        assert node.state.get_balance(alice) == 975
        assert node.state.get_balance(bob) == 25


def test_t2_duplicates_and_reordering_do_not_split_the_chain():
    _simulator, result = _run("T2_duplicate_reordered.json")
    assert result.converged
    assert result.safety_holds


def test_t3_bad_signature_and_wrong_domain_are_logged_and_rejected():
    simulator = BlockchainSimulator(_config("T3_bad_signature_domain.json"))
    validator = simulator.validators[0]
    invalid_signature = Vote(
        1, 0, Phase.PREVOTE, "bad-block", validator,
        signature="00", chain_id=simulator.chain_id,
    )
    wrong_domain = sign_vote(
        Vote(1, 0, Phase.PREVOTE, "bad-block", validator,
             chain_id="another-chain"),
        simulator.validator_private_keys[validator],
    )
    simulator.inject_vote(invalid_signature)
    simulator.inject_vote(wrong_domain)
    simulator.run()
    reasons = {
        row.get("reason") for row in simulator.event_log.records
        if row.get("event") == "VOTE_REJECTED"
    }
    assert "invalid_signature" in reasons
    assert "wrong_domain" in reasons


def test_t4_replayed_transaction_is_applied_only_once():
    simulator = BlockchainSimulator(_config("T4_transaction_replay.json"))
    tx = simulator.demo_transaction
    assert tx is not None
    assert not simulator.nodes[simulator.validators[0]].submit_transaction(tx)
    result = simulator.run()
    assert result.converged
    alice = simulator.participant_public_keys["alice"]
    bob = simulator.participant_public_keys["bob"]
    for node in simulator.nodes.values():
        included = [
            item for block in node.ledger[1:]
            for item in block.transactions
            if item == tx
        ]
        assert len(included) == 1
        assert node.state.get_balance(alice) == 975
        assert node.state.get_balance(bob) == 25


def test_t5_pre_synchrony_faults_preserve_safety_and_recover():
    _simulator, result = _run("T5_pre_synchrony_faults.json")
    assert result.safety_holds
    assert result.converged


def test_t6_silent_proposer_times_out_and_chain_continues():
    simulator, result = _run("T6_silent_proposer.json")
    assert result.converged
    assert result.safety_holds
    events = [row.get("event") for row in simulator.event_log.records]
    assert "PROPOSER_SILENT" in events
    assert "ROUND_TIMEOUT" in events
    assert "ROUND_CHANGE" in events


def test_t7_byzantine_proposer_equivocation_cannot_finalize_conflicts():
    simulator, result = _run("T7_byzantine_equivocation.json")
    events = [row.get("event") for row in simulator.event_log.records]
    assert "BYZANTINE_EQUIVOCATION" in events
    assert result.safety_holds
    assert result.converged


def test_t8_same_seed_reproduces_log_bytes_and_final_state_hash():
    result = check_determinism(ROOT / "scenarios" / "T8_replay.json")
    assert result["logs_identical"]
    assert result["final_state_hash_equal"]
    assert result["first_converged"]
    assert result["second_converged"]
