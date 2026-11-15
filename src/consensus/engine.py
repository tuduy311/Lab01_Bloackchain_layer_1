"""BFT state machine: proposal, prevote, precommit, and finalization."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Iterable, Optional, Tuple

from src.consensus.locking import LockState, Polka, VoteGuard
from src.consensus.proposer import ProposerSelector
from src.crypto import verify_block_id, verify_block_signature, verify_vote_signature
from src.models import (
    Block,
    FinalizeCertificate,
    NIL_BLOCK_ID,
    Phase,
    Vote,
)


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

    The engine is transport-independent: callers pass proposals and votes to
    it and broadcast the returned vote/certificate through their network
    adapter.  ``require_signatures`` can be enabled when validator ids are
    Ed25519 public keys; it defaults to ``False`` so deterministic simulations
    can use symbolic validator ids.
    """

    def __init__(
        self,
        node_id: str,
        validators: Iterable[str],
        height: int = 1,
        parent_id: str = "",
        proposer_selector: Optional[ProposerSelector] = None,
        require_signatures: bool = False,
        block_validator: Optional[Callable[[Block], bool]] = None,
        public_key_resolver: Optional[Callable[[str], str]] = None,
        vote_signer: Optional[Callable[[Vote], Vote]] = None,
    ) -> None:
        self.node_id = node_id
        self.validators = tuple(validators)
        if not self.validators or len(set(self.validators)) != len(self.validators):
            raise ValueError("validators must be a non-empty sequence of unique ids")
        if node_id not in self.validators:
            raise ValueError("node_id must belong to validators")
        if height < 0:
            raise ValueError("height must be >= 0")
        self.quorum = len(self.validators) - (len(self.validators) - 1) // 3
        self.selector = proposer_selector or ProposerSelector(self.validators)
        self.require_signatures = require_signatures
        self.block_validator = block_validator
        self.public_key_resolver = public_key_resolver or (lambda validator: validator)
        self.vote_signer = vote_signer or (lambda vote: vote)
        self.parent_id = parent_id
        self.state = ConsensusState(height=height)
        self.lock = LockState()
        self.votes = VoteGuard(self.validators)
        self.blocks: Dict[str, Block] = {}
        self.polkas: Dict[Tuple[int, int, str], Polka] = {}
        self.finalized: Dict[int, FinalizeCertificate] = {}

    # -- state properties -------------------------------------------------

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

    # -- proposal and local votes ----------------------------------------

    def accept_proposal(
        self, block: Block, *, proposal_round: Optional[int] = None,
        proposer_id: Optional[str] = None, valid_round_polka: Optional[Polka] = None,
    ) -> bool:
        """Accept a block, including an unchanged block re-proposed later.

        The transport must authenticate the *current* proposal envelope. The
        block's original signature and any previous-round proof are checked
        here. Block.round remains its creation round, preserving its hash.
        """
        round_ = block.round if proposal_round is None else proposal_round
        proposer = block.proposer_id if proposer_id is None else proposer_id
        if block.height != self.height or round_ != self.round:
            return False
        if block.round < 0 or block.round > round_:
            return False
        if self.selector.proposer_for(block.height, round_) != proposer:
            return False
        if self.selector.proposer_for(block.height, block.round) != block.proposer_id:
            return False
        if block.parent_id != self.parent_id or not verify_block_id(block):
            return False
        if self.require_signatures and not verify_block_signature(
            block, self.public_key_resolver(block.proposer_id)
        ):
            return False
        if self.block_validator is not None and not self.block_validator(block):
            return False
        if block.round < round_ and valid_round_polka is None:
            return False
        if valid_round_polka is not None:
            if (
                not self.verify_polka(valid_round_polka)
                or valid_round_polka.height != self.height
                or valid_round_polka.block_id != block.block_id
                or not block.round <= valid_round_polka.round < round_
            ):
                return False
        if not self.lock.can_prevote(block.block_id, round_, valid_round_polka):
            return False
        if valid_round_polka is not None:
            self.polkas[(self.height, valid_round_polka.round, block.block_id)] = valid_round_polka
        self.blocks[block.block_id] = block
        self.state.phase = Phase.PREVOTE
        return True

    # Compatibility alias used by network adapters.
    handle_proposal = accept_proposal

    def make_prevote(self, block_id: Optional[str] = None) -> Vote:
        """Create this validator's single prevote for the current slot."""
        if self.state.phase not in (Phase.PROPOSAL, Phase.PREVOTE):
            raise ValueError("cannot prevote after leaving the prevote phase")
        candidate = block_id or self.lock.locked_block_id or NIL_BLOCK_ID
        if candidate != NIL_BLOCK_ID and (
            candidate not in self.blocks or self.blocks[candidate].height != self.height
        ):
            raise ValueError("cannot prevote an unknown block")
        proofs = [p for p in self.polkas.values()
                  if p.height == self.height and p.block_id == candidate and p.round <= self.round]
        polka = max(proofs, key=lambda p: p.round, default=None)
        if not self.lock.can_prevote(candidate, self.round, polka):
            candidate = self.lock.locked_block_id or NIL_BLOCK_ID
        vote = self.vote_signer(Vote(self.height, self.round, Phase.PREVOTE, candidate, self.node_id))
        if not self.votes.add(vote):
            raise ValueError("validator already prevoted this height and round")
        self.state.phase = Phase.PREVOTE
        return vote

    def make_precommit(self, block_id: Optional[str] = None) -> Vote:
        """Create a precommit only for a block with a current-round polka."""
        candidate = block_id or self.lock.locked_block_id or NIL_BLOCK_ID
        if candidate != NIL_BLOCK_ID and (
            (self.height, self.round, candidate) not in self.polkas
        ):
            raise ValueError("precommit requires a quorum prevote polka")
        vote = self.vote_signer(Vote(self.height, self.round, Phase.PRECOMMIT, candidate, self.node_id))
        if not self.votes.add(vote):
            raise ValueError("validator already precommitted this height and round")
        self.state.phase = Phase.PRECOMMIT
        return vote

    # -- incoming votes ---------------------------------------------------

    def receive_vote(self, vote: Vote) -> Optional[object]:
        """Process one vote and return a precommit or finalize certificate."""
        if vote.height != self.height or vote.round < self.round:
            return None
        if vote.round != self.round or vote.phase not in (
            Phase.PREVOTE,
            Phase.PRECOMMIT,
        ):
            return None
        if vote.voter_id not in self.validators:
            return None
        if self.require_signatures and not verify_vote_signature(
            vote, self.public_key_resolver(vote.voter_id)
        ):
            return None
        if not self.votes.add(vote):
            return None

        if vote.phase == Phase.PREVOTE:
            return self._on_prevote(vote)
        return self._on_precommit(vote)

    # Compatibility alias used by network adapters.
    handle_vote = receive_vote

    def _on_prevote(self, vote: Vote) -> Optional[Vote]:
        if (vote.block_id == NIL_BLOCK_ID or vote.block_id not in self.blocks
                or self.blocks[vote.block_id].height != vote.height):
            return None
        if self.votes.count(
            vote.height, vote.round, Phase.PREVOTE, vote.block_id
        ) < self.quorum:
            return None
        votes = self.votes.votes(
            vote.height, vote.round, Phase.PREVOTE, vote.block_id
        )
        polka = Polka(vote.height, vote.round, vote.block_id, votes)
        self.polkas[(vote.height, vote.round, vote.block_id)] = polka
        self.lock.apply_polka(polka)
        self._sync_lock_state()
        self.state.phase = Phase.PRECOMMIT
        if self.node_id not in {item.voter_id for item in votes}:
            return None
        if self.votes.has(self.height, self.round, Phase.PRECOMMIT, self.node_id):
            return None
        return self.make_precommit(vote.block_id)

    def _on_precommit(self, vote: Vote) -> Optional[FinalizeCertificate]:
        if vote.block_id != NIL_BLOCK_ID and (
            (vote.height, vote.round, vote.block_id) not in self.polkas
            or vote.block_id not in self.blocks
            or self.blocks[vote.block_id].height != vote.height
        ):
            return None
        if self.votes.count(
            vote.height, vote.round, Phase.PRECOMMIT, vote.block_id
        ) < self.quorum:
            return None
        if vote.block_id == NIL_BLOCK_ID:
            self._advance_round()
            return None
        if vote.height in self.finalized:
            return None
        precommits = self.votes.votes(
            vote.height, vote.round, Phase.PRECOMMIT, vote.block_id
        )
        certificate = FinalizeCertificate(
            vote.height, vote.round, vote.block_id, precommits
        )
        self.finalized[vote.height] = certificate
        self.state.phase = Phase.FINALIZE
        self._advance_height(certificate)
        return certificate

    def poll(self) -> Tuple[object, ...]:
        """Evaluate stored votes after a local vote or reordered delivery.

        Local votes are already in VoteGuard, so feeding them back through
        receive_vote would only hit deduplication. This method never re-signs
        or re-broadcasts a vote and may return a precommit and certificate.
        """
        actions = []
        slot = (self.height, self.round)
        for vote in self.votes.votes(*slot, Phase.PREVOTE):
            action = self._on_prevote(vote)
            if action is not None:
                actions.append(action)
        for vote in self.votes.votes(*slot, Phase.PRECOMMIT):
            action = self._on_precommit(vote)
            if action is not None:
                actions.append(action)
            if (self.height, self.round) != slot:
                break
        return tuple(actions)

    def _verify_quorum(self, votes, height: int, round_: int, phase: Phase, block_id: str) -> bool:
        if height < 0 or round_ < 0 or not block_id or block_id == NIL_BLOCK_ID:
            return False
        seen = set()
        for vote in votes:
            if (vote.voter_id in seen or vote.voter_id not in self.validators
                    or (vote.height, vote.round, vote.phase, vote.block_id)
                    != (height, round_, phase, block_id)):
                return False
            if self.require_signatures and not verify_vote_signature(
                vote, self.public_key_resolver(vote.voter_id)
            ):
                return False
            seen.add(vote.voter_id)
        return len(seen) >= self.quorum

    def verify_polka(self, polka: Polka) -> bool:
        return self._verify_quorum(
            polka.votes, polka.height, polka.round, Phase.PREVOTE, polka.block_id
        )

    def verify_certificate(self, certificate: FinalizeCertificate) -> bool:
        """A signed precommit quorum can be verified without local vote history."""
        return self._verify_quorum(
            certificate.precommits, certificate.height, certificate.round,
            Phase.PRECOMMIT, certificate.block_id,
        )

    def accept_finalize(self, block: Block, certificate: FinalizeCertificate) -> bool:
        """Catch up one height from a fully verified block and certificate."""
        if (block.height != self.height or certificate.height != self.height
                or block.block_id != certificate.block_id
                or not 0 <= block.round <= certificate.round
                or block.parent_id != self.parent_id
                or block.proposer_id != self.selector.proposer_for(block.height, block.round)
                or not verify_block_id(block) or not self.verify_certificate(certificate)):
            return False
        if self.require_signatures and not verify_block_signature(
            block, self.public_key_resolver(block.proposer_id)
        ):
            return False
        if self.block_validator is not None and not self.block_validator(block):
            return False
        if block.height in self.finalized:
            return False
        self.blocks[block.block_id] = block
        self.finalized[block.height] = certificate
        self._advance_height(certificate)
        return True

    def _advance_height(self, certificate: FinalizeCertificate) -> None:
        block = self.blocks.get(certificate.block_id)
        self.parent_id = certificate.block_id
        self.state = ConsensusState(height=certificate.height + 1)
        self.lock.reset()
        self.votes.clear_before(self.state.height)
        self.polkas.clear()
        if block is not None:
            self.blocks = {block.block_id: block}
        else:
            self.blocks = {}

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
