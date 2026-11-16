"""Tests for consensus safety and locking rules."""

import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.consensus.engine import ConsensusEngine
from src.consensus.locking import LockState, Polka
from src.crypto import compute_block_id
from src.models import Block, NIL_BLOCK_ID, Phase, Vote


VALIDATORS = ("v1", "v2", "v3", "v4")


def _engine():
    return ConsensusEngine("v1", VALIDATORS, height=1, parent_id="genesis")


def _proposal(engine, round=0, block_id="block"):
    proposer = engine.selector.proposer_for(1, round)
    block = Block(
        height=1,
        round=round,
        parent_id="genesis",
        proposer_id=proposer,
    )
    return Block(
        height=block.height,
        round=block.round,
        parent_id=block.parent_id,
        transactions=block.transactions,
        proposer_id=block.proposer_id,
        timestamp=block.timestamp,
        block_id=compute_block_id(block),
    )


class TestLocking:
    def test_lock_requires_polka_and_nil_does_not_unlock(self):
        state = LockState()
        polka = Polka(
            1, 0, "A",
            tuple(Vote(1, 0, Phase.PREVOTE, "A", voter)
                  for voter in VALIDATORS[:3]),
        )
        assert state.apply_polka(polka)
        assert state.locked_block_id == "A"
        assert not state.can_prevote("B", 1)
        assert not state.can_prevote(NIL_BLOCK_ID, 1)

    def test_higher_round_polka_unlocks(self):
        state = LockState(locked_block_id="A", locked_round=0)
        polka = Polka(
            1, 1, "B",
            tuple(Vote(1, 1, Phase.PREVOTE, "B", voter)
                  for voter in VALIDATORS[:3]),
        )
        assert state.can_prevote("B", 1, polka)
        assert state.apply_polka(polka)
        assert (state.locked_block_id, state.locked_round) == ("B", 1)


class TestConsensusEngine:
    def test_duplicate_and_conflicting_votes_count_once(self):
        engine = _engine()
        first = Vote(1, 0, Phase.PREVOTE, "A", "v2")
        conflicting = Vote(1, 0, Phase.PREVOTE, "B", "v2")
        assert engine.receive_vote(first) is None
        assert engine.receive_vote(first) is None
        assert engine.receive_vote(conflicting) is None
        assert len(engine.vote_pool.get_votes(1, 0, Phase.PREVOTE, "A")) == 1
        assert len(engine.vote_pool.conflicts) == 1

    def test_precommit_requires_polka_and_finalize_requires_quorum(self):
        engine = _engine()
        block = _proposal(engine, block_id="A")
        assert engine.accept_proposal(block)

        assert         engine.receive_vote(
            Vote(1, 0, Phase.PRECOMMIT, block.block_id, "v2")
        ) is None

        engine.receive_vote(Vote(1, 0, Phase.PREVOTE, block.block_id, "v1"))
        engine.receive_vote(Vote(1, 0, Phase.PREVOTE, block.block_id, "v2"))
        generated = engine.receive_vote(
            Vote(1, 0, Phase.PREVOTE, block.block_id, "v3")
        )
        assert generated is not None
        assert engine.lock.locked_block_id == block.block_id

        assert engine.receive_vote(
            Vote(1, 0, Phase.PRECOMMIT, block.block_id, "v2")
        ) is None
        certificate = engine.receive_vote(
            Vote(1, 0, Phase.PRECOMMIT, block.block_id, "v3")
        )
        assert certificate is not None
        assert certificate.block_id == block.block_id
        assert engine.height == 2
        assert engine.parent_id == block.block_id

        # A second certificate for the old height cannot be produced.
        assert engine.receive_vote(
            Vote(1, 0, Phase.PRECOMMIT, block.block_id, "v4")
        ) is None

    def test_timeout_advances_only_current_round(self):
        engine = _engine()
        assert not engine.on_timeout(1, 1)
        assert engine.round == 0
        assert engine.on_timeout(1, 0)
        assert engine.round == 1

