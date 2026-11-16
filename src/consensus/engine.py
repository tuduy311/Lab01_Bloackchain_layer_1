"""Authenticated, transport-independent BFT consensus state machine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Iterable, Mapping, Optional, Tuple

from src.consensus.locking import LockState, Polka
from src.consensus.proposer import ProposerSelector
from src.consensus.vote_pool import VotePool
from src.crypto import (
    sign_vote,
    verify_block_id,
    verify_block_signature,
    verify_vote_signature,
)
from src.models import Block, FinalizeCertificate, NIL_BLOCK_ID, Phase, Vote


def quorum_size(validator_count: int) -> int:
    """Return ``n-f`` where ``f=floor((n-1)/3)``.

    This is 2f+1 for n=3f+1 and remains safe for supported sizes such as 8,
    which is not itself of the form 3f+1.
    """
    if validator_count < 1:
        raise ValueError("validator_count must be positive")
    faults = (validator_count - 1) // 3
    return validator_count - faults


@dataclass
class ConsensusState:
    """Mutable consensus view for the current height and round."""

    height: int
    round: int = 0
    phase: Phase = Phase.PROPOSAL
    locked_block_id: Optional[str] = None
    locked_round: Optional[int] = None
    valid_block_id: Optional[str] = None
    valid_round: Optional[int] = None


class ConsensusEngine:
    """Single-validator BFT state machine.

    Applications provide a deterministic ``block_validator`` and transport
    signed blocks, votes and certificates between engines.  Signature checks
    are enabled by default.  Symbolic-ID unit tests can opt out explicitly.
    """

    def __init__(
        self,
        node_id: str,
        validators: Iterable[str],
        height: int = 1,
        parent_id: str = "",
        proposer_selector: Optional[ProposerSelector] = None,
        require_signatures: bool = True,
        block_validator: Optional[Callable[[Block], bool]] = None,
        *,
        chain_id: str = "lab01",
        validator_public_keys: Optional[Mapping[str, str]] = None,
        private_key: Optional[str] = None,
    ) -> None:
        self.node_id = node_id
        self.validators = tuple(validators)
        if not self.validators or len(set(self.validators)) != len(self.validators):
            raise ValueError("validators must be a non-empty sequence of unique ids")
        if node_id not in self.validators:
            raise ValueError("node_id must belong to validators")
        if height < 0:
            raise ValueError("height must be >= 0")
        self.quorum = quorum_size(len(self.validators))
        self.selector = proposer_selector or ProposerSelector(self.validators)
        if tuple(self.selector.validators) != self.validators:
            raise ValueError("proposer selector validator order must match validators")
        self.require_signatures = require_signatures
        self.validator_public_keys = dict(validator_public_keys or {})
        if not self.validator_public_keys:
            # This is useful when validator IDs are themselves public keys.
            self.validator_public_keys = {validator: validator for validator in self.validators}
        self.private_key = private_key
        self.chain_id = chain_id
        self.block_validator = block_validator
        self.parent_id = parent_id
        self.state = ConsensusState(height=height)
        self.lock = LockState()
        self.votes = VotePool(self.validators)
        self.blocks: Dict[str, Block] = {}
        self.polkas: Dict[Tuple[int, int, str], Polka] = {}
        self.finalized: Dict[int, FinalizeCertificate] = {}

    @property
    def height(self) -> int:
        return self.state.height

    @property
    def round(self) -> int:
        return self.state.round

    @property
    def phase(self) -> Phase:
        return self.state.phase

    @property
    def finalized_block_id(self) -> Optional[str]:
        certificate = self.finalized.get(self.height - 1)
        return certificate.block_id if certificate else None

    def _sync_lock_state(self) -> None:
        self.state.locked_block_id = self.lock.locked_block_id
        self.state.locked_round = self.lock.locked_round
        self.state.valid_block_id = self.lock.valid_block_id
        self.state.valid_round = self.lock.valid_round

    def _advance_round(self) -> None:
        self.state.round += 1
        self.state.phase = Phase.PROPOSAL

    def _sign_vote(self, vote: Vote) -> Vote:
        if not self.require_signatures:
            return vote
        if not self.private_key:
            raise ValueError("a private key is required to sign consensus votes")
        return sign_vote(vote, self.private_key)

    def _valid_vote(self, vote: Vote, phase: Optional[Phase] = None) -> bool:
        return self.vote_rejection_reason(vote, phase) == ""

    def vote_rejection_reason(self, vote: Vote,
                              phase: Optional[Phase] = None) -> str:
        """Return an auditable rejection reason, or the empty string."""
        if vote.chain_id != self.chain_id:
            return "wrong_domain"
        if vote.voter_id not in self.validators:
            return "unknown_validator"
        if vote.height < 0 or vote.round < 0:
            return "invalid_slot"
        if vote.phase not in (Phase.PREVOTE, Phase.PRECOMMIT):
            return "invalid_phase"
        if phase is not None and vote.phase != phase:
            return "wrong_phase"
        if self.require_signatures:
            public_key = self.validator_public_keys.get(vote.voter_id)
            if not public_key or not verify_vote_signature(vote, public_key):
                return "invalid_signature"
        return ""

    def _valid_polka(
        self,
        height: int,
        round: int,
        block_id: str,
        votes: Iterable[Vote],
    ) -> Optional[Polka]:
        if block_id == NIL_BLOCK_ID:
            return None
        accepted: Dict[str, Vote] = {}
        for vote in votes:
            if (
                not self._valid_vote(vote, Phase.PREVOTE)
                or (vote.height, vote.round, vote.block_id)
                != (height, round, block_id)
                or vote.voter_id in accepted
            ):
                return None
            accepted[vote.voter_id] = vote
        if len(accepted) < self.quorum:
            return None
        return Polka(height, round, block_id,
                     tuple(accepted[key] for key in sorted(accepted)))

    def accept_proposal(
        self,
        block: Block,
        valid_round: Optional[int] = None,
        prevote_proof: Iterable[Vote] = (),
    ) -> bool:
        """Validate and retain a proposal, including an optional unlock proof."""
        if (
            block.height != self.height
            or block.round < self.round
            or block.round > self.round + 1
            or (self.phase not in (Phase.PROPOSAL, Phase.PREVOTE)
                and not (block.round == self.round + 1
                         and self.phase == Phase.PRECOMMIT))
            or block.chain_id != self.chain_id
            or self.selector.proposer_for(block.height, block.round) != block.proposer_id
            or block.parent_id != self.parent_id
            or not verify_block_id(block)
        ):
            return False
        if self.require_signatures:
            proposer_key = self.validator_public_keys.get(block.proposer_id)
            if not proposer_key or not verify_block_signature(block, proposer_key):
                return False
        if self.block_validator is not None and not self.block_validator(block):
            return False

        polka = None
        proof_votes = tuple(prevote_proof)
        if valid_round is not None:
            if valid_round < 0 or valid_round >= block.round:
                return False
            polka = self._valid_polka(block.height, valid_round,
                                      block.block_id, proof_votes)
            if polka is None:
                return False
            self.polkas[(block.height, valid_round, block.block_id)] = polka

        if not self.lock.can_prevote(block.block_id, block.round, polka):
            return False
        self.blocks[block.block_id] = block
        if polka is not None:
            self.lock.apply_polka(polka)
            self._sync_lock_state()
        if block.round > self.round:
            self.state.round = block.round
        self.state.phase = Phase.PREVOTE
        return True

    handle_proposal = accept_proposal

    def make_prevote(self, block_id: Optional[str] = None) -> Vote:
        """Create and record this validator's one prevote for the slot."""
        if self.phase not in (Phase.PROPOSAL, Phase.PREVOTE):
            raise ValueError("cannot prevote after leaving the prevote phase")
        candidate = (block_id if block_id is not None else
                     self.lock.locked_block_id or NIL_BLOCK_ID)
        if candidate != NIL_BLOCK_ID:
            block = self.blocks.get(candidate)
            if block is None or block.height != self.height or not verify_block_id(block):
                raise ValueError("cannot prevote for a block that was not validated")
            polkas = [p for (h, r, bid), p in self.polkas.items()
                      if h == self.height and bid == candidate and r < self.round]
            proof = max(polkas, key=lambda p: p.round) if polkas else None
            if not self.lock.can_prevote(candidate, self.round, proof):
                raise ValueError("lock rules prohibit this prevote")
        vote = self._sign_vote(Vote(
            self.height, self.round, Phase.PREVOTE, candidate, self.node_id,
            chain_id=self.chain_id,
        ))
        if not self.votes.add(vote):
            raise ValueError("validator already prevoted this height and round")
        self.state.phase = Phase.PREVOTE
        return vote

    def make_precommit(self, block_id: Optional[str] = None) -> Vote:
        """Create and record one precommit, requiring a polka for blocks."""
        candidate = (block_id if block_id is not None else
                     self.lock.locked_block_id or NIL_BLOCK_ID)
        if candidate != NIL_BLOCK_ID:
            if (self.height, self.round, candidate) not in self.polkas:
                raise ValueError("precommit requires a quorum prevote polka")
            if candidate not in self.blocks:
                raise ValueError("cannot precommit for an unknown block")
            if (self.lock.locked_block_id != candidate
                    or self.lock.locked_round != self.round):
                raise ValueError("lock rules prohibit this precommit")
        vote = self._sign_vote(Vote(
            self.height, self.round, Phase.PRECOMMIT, candidate, self.node_id,
            chain_id=self.chain_id,
        ))
        if not self.votes.add(vote):
            raise ValueError("validator already precommitted this height and round")
        self.state.phase = Phase.PRECOMMIT
        return vote

    def receive_vote(
        self,
        vote: Vote,
        prevote_proof: Iterable[Vote] = (),
    ) -> Optional[object]:
        """Process a signed vote and return a local vote or finalize certificate."""
        if vote.height != self.height or vote.round != self.round:
            return None
        if not self._valid_vote(vote) or not self.votes.add(vote):
            return None
        if vote.phase == Phase.PREVOTE:
            return self._on_prevote(vote)

        if vote.block_id != NIL_BLOCK_ID:
            key = (vote.height, vote.round, vote.block_id)
            generated = None
            if key not in self.polkas:
                polka = self._valid_polka(vote.height, vote.round,
                                          vote.block_id, prevote_proof)
                if polka is None:
                    self.votes.remove(vote)
                    return None
                self.polkas[key] = polka
                if vote.block_id in self.blocks:
                    self.lock.apply_polka(polka)
                    self._sync_lock_state()
                    if (self.lock.locked_block_id == vote.block_id
                            and self.lock.locked_round == vote.round
                            and not self.votes.has(vote.height, vote.round,
                                                   Phase.PRECOMMIT, self.node_id)):
                        generated = self.make_precommit(vote.block_id)
            certificate = self._on_precommit(vote)
            return certificate if certificate is not None else generated
        return self._on_precommit(vote)

    handle_vote = receive_vote

    def process_pending_prevotes(self, block_id: str) -> Optional[Vote]:
        """Re-check a quorum that arrived before its proposal body."""
        if self.votes.count(self.height, self.round, Phase.PREVOTE,
                            block_id) < self.quorum:
            return None
        return self._process_polka(self.height, self.round, block_id)

    def process_pending_block(
        self, block_id: str
    ) -> Tuple[Optional[Vote], Optional[FinalizeCertificate]]:
        """Apply buffered proof effects after a delayed proposal body arrives."""
        if block_id not in self.blocks:
            return None, None
        vote = None
        current_key = (self.height, self.round, block_id)
        if current_key in self.polkas:
            self.lock.apply_polka(self.polkas[current_key])
            self._sync_lock_state()
        if (current_key in self.polkas
                and self.lock.locked_block_id == block_id
                and self.lock.locked_round == self.round):
            if not self.votes.has(self.height, self.round,
                                  Phase.PRECOMMIT, self.node_id):
                vote = self.make_precommit(block_id)
        elif self.votes.count(self.height, self.round, Phase.PREVOTE,
                              block_id) >= self.quorum:
            vote = self._process_polka(self.height, self.round, block_id)
        precommit_votes = self.votes.votes(self.height, self.round,
                                           Phase.PRECOMMIT, block_id)
        if len(precommit_votes) >= self.quorum:
            certificate = self._on_precommit(precommit_votes[-1])
            if certificate is not None:
                return vote, certificate
        return vote, None

    def _on_prevote(self, vote: Vote) -> Optional[Vote]:
        if vote.block_id == NIL_BLOCK_ID:
            return None
        if self.votes.count(vote.height, vote.round, Phase.PREVOTE,
                            vote.block_id) < self.quorum:
            return None
        return self._process_polka(vote.height, vote.round, vote.block_id)

    def _process_polka(self, height: int, round: int,
                       block_id: str) -> Optional[Vote]:
        if block_id not in self.blocks:
            return None
        votes = self.votes.votes(height, round, Phase.PREVOTE, block_id)
        polka = self._valid_polka(height, round, block_id, votes)
        if polka is None:
            return None
        self.polkas[(height, round, block_id)] = polka
        self.lock.apply_polka(polka)
        self._sync_lock_state()
        if (self.lock.locked_block_id != block_id
                or self.lock.locked_round != round):
            return None
        self.state.phase = Phase.PRECOMMIT
        if self.votes.has(height, round, Phase.PRECOMMIT, self.node_id):
            return None
        return self.make_precommit(block_id)

    def _on_precommit(self, vote: Vote) -> Optional[FinalizeCertificate]:
        if vote.block_id == NIL_BLOCK_ID:
            if self.votes.count(vote.height, vote.round, Phase.PRECOMMIT,
                                NIL_BLOCK_ID) >= self.quorum:
                self._advance_round()
            return None
        key = (vote.height, vote.round, vote.block_id)
        if key not in self.polkas or vote.block_id not in self.blocks:
            return None
        if self.votes.count(vote.height, vote.round, Phase.PRECOMMIT,
                            vote.block_id) < self.quorum:
            return None
        if vote.height in self.finalized:
            return None
        polka = self.polkas[key]
        precommits = self.votes.votes(vote.height, vote.round,
                                      Phase.PRECOMMIT, vote.block_id)
        certificate = FinalizeCertificate(
            vote.height, vote.round, vote.block_id, precommits,
            prevotes=polka.votes,
        )
        self._commit(certificate)
        return certificate

    def verify_finalize_certificate(self, certificate: FinalizeCertificate,
                                     block: Block) -> bool:
        """Check both quorum proofs and the block before accepting a commit."""
        if (
            certificate.height != self.height
            or certificate.block_id != block.block_id
            or certificate.round != block.round
            or block.height != self.height
            or block.chain_id != self.chain_id
            or block.parent_id != self.parent_id
            or not verify_block_id(block)
        ):
            return False
        proposer = self.selector.proposer_for(block.height, block.round)
        if block.proposer_id != proposer:
            return False
        if self.require_signatures:
            key = self.validator_public_keys.get(proposer)
            if not key or not verify_block_signature(block, key):
                return False
        if self.block_validator is not None and not self.block_validator(block):
            return False
        if self._valid_polka(block.height, certificate.round, block.block_id,
                             certificate.prevotes) is None:
            return False
        accepted: set[str] = set()
        for vote in certificate.precommits:
            if (
                not self._valid_vote(vote, Phase.PRECOMMIT)
                or (vote.height, vote.round, vote.block_id)
                != (certificate.height, certificate.round, certificate.block_id)
                or vote.voter_id in accepted
            ):
                return False
            accepted.add(vote.voter_id)
        return len(accepted) >= self.quorum

    def commit_certificate(self, certificate: FinalizeCertificate,
                           block: Block) -> bool:
        """Commit a verified certificate received from another validator."""
        if not self.verify_finalize_certificate(certificate, block):
            return False
        self.blocks[block.block_id] = block
        self._commit(certificate)
        return True

    def _commit(self, certificate: FinalizeCertificate) -> None:
        self.finalized[certificate.height] = certificate
        self.parent_id = certificate.block_id
        next_height = certificate.height + 1
        self.state = ConsensusState(height=next_height)
        self.lock.reset()
        self.votes.clear_before(next_height)
        self.polkas.clear()
        self.blocks.clear()

    def on_timeout(self, height: int, round: int) -> bool:
        """Move to the next round if the timeout belongs to the current slot."""
        if (height, round) != (self.height, self.round):
            return False
        self._advance_round()
        return True

    def reset_height(self, height: int, parent_id: str = "") -> None:
        """Reset the engine for an externally selected height."""
        if height < 0:
            raise ValueError("height must be >= 0")
        self.parent_id = parent_id
        self.state = ConsensusState(height=height)
        self.lock.reset()
        self.votes.clear_before(height)
        self.polkas.clear()
        self.blocks.clear()
