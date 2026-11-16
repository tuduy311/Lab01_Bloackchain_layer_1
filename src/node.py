"""A validator node that connects consensus, execution and simulated P2P."""

from __future__ import annotations

from typing import Dict, Iterable, Optional, Tuple

from src.consensus.engine import ConsensusEngine
from src.consensus.proposer import ProposerSelector
from src.consensus.timeout import TimeoutConfig, TimeoutManager
from src.crypto import sha256_hex, sign_block, verify_transaction_signature
from src.crypto import sign_vote
from src.logger import EventLog
from src.execution import WorldState, apply_transaction, execute_block
from src.models import (
    Block,
    FinalizeCertificate,
    NIL_BLOCK_ID,
    Phase,
    Transaction,
    Vote,
)
from src.network.network import (
    KIND_BODY,
    KIND_BODY_REQUEST,
    KIND_HEADER,
    Network,
    NetworkEnvelope,
)
from src.scheduler import Scheduler


class Node:
    """One validator with a private ledger, state, mempool and consensus view."""

    def __init__(
        self,
        node_id: str,
        validators: Iterable[str],
        network: Network,
        scheduler: Scheduler,
        logger: EventLog,
        initial_state: WorldState,
        genesis: Block,
        private_key: str,
        validator_public_keys: Dict[str, str],
        *,
        chain_id: str = "lab01",
        proposer_seed: int = 0,
        timeout_config: Optional[TimeoutConfig] = None,
        silent_slots: Iterable[Tuple[int, int]] = (),
        equivocate_slots: Iterable[Tuple[int, int]] = (),
    ) -> None:
        self.node_id = node_id
        self.validators = tuple(validators)
        self.network = network
        self.scheduler = scheduler
        self.logger = logger
        self.chain_id = chain_id
        self.silent_slots = set(silent_slots)
        self.equivocate_slots = set(equivocate_slots)
        self.private_key = private_key
        self.validator_public_keys = dict(validator_public_keys)
        self.state = initial_state.copy()
        self.ledger = [genesis]
        self.state_roots: Dict[int, str] = {genesis.height: self.state.state_root()}
        self.mempool: Dict[str, Transaction] = {}
        self._committed_tx_ids: set[str] = set()
        self._block_cache: Dict[str, Block] = {}
        self._proposal_bodies: Dict[str, dict] = {}
        self._seen_bodies: set[str] = set()
        self._pending_certificates: Dict[int, Tuple[FinalizeCertificate, Block]] = {}
        self._proposal_seen: Dict[Tuple[int, int], str] = {}
        self._future_votes: Dict[Tuple[int, int], list] = {}
        self.selector = ProposerSelector(self.validators, seed=proposer_seed)

        self.engine = ConsensusEngine(
            node_id,
            self.validators,
            height=1,
            parent_id=genesis.block_id,
            proposer_selector=self.selector,
            require_signatures=True,
            block_validator=self._validate_block,
            chain_id=chain_id,
            validator_public_keys=self.validator_public_keys,
            private_key=private_key,
        )
        self.timer = TimeoutManager(
            scheduler, self._on_timeout, timeout_config or TimeoutConfig()
        )
        self.network.set_receiver(node_id, self.receive)

    @property
    def height(self) -> int:
        return self.engine.height

    @property
    def round(self) -> int:
        return self.engine.round

    @property
    def head(self) -> Block:
        return self.ledger[-1]

    @property
    def state_root(self) -> str:
        return self.state.state_root()

    def start(self) -> None:
        self._log("NODE_START", height=self.height, round=self.round,
                  parent_id=self.engine.parent_id)
        self._enter_round()

    def submit_transaction(self, tx: Transaction) -> bool:
        """Accept one user transaction locally and gossip it through the network."""
        if not self._valid_transaction(tx):
            self._log("TX_REJECTED", height=self.height, round=self.round,
                      reason="invalid_signature_or_chain", tx_id=self._tx_id(tx))
            return False
        tx_id = self._tx_id(tx)
        if tx_id in self._committed_tx_ids:
            self._log("TX_DUPLICATE", height=self.height, round=self.round,
                      reason="already_committed", tx_id=tx_id)
            return False
        if tx_id in self.mempool:
            self._log("TX_DUPLICATE", height=self.height, round=self.round,
                      tx_id=tx_id)
            return False
        self.mempool[tx_id] = tx
        self._log("TX_ACCEPTED", height=self.height, round=self.round,
                  tx_id=tx_id)
        self.network.broadcast(
            self.node_id, tx.to_dict(), kind="TX", height=self.height
        )
        return True

    def receive(self, node_id: str, envelope: NetworkEnvelope) -> None:
        """Handle one delivered network envelope."""
        if node_id != self.node_id:
            return
        kind = envelope.kind
        if kind == "TX":
            self._receive_transaction(envelope)
        elif kind == KIND_HEADER:
            self._receive_header(envelope)
        elif kind == KIND_BODY_REQUEST:
            self._receive_body_request(envelope)
        elif kind == KIND_BODY:
            self._receive_body(envelope)
        elif kind in (Phase.PREVOTE.value, Phase.PRECOMMIT.value):
            self._receive_vote(envelope)
        elif kind == "FINALIZE":
            self._receive_finalize(envelope)

    def _log(self, event: str, *, height: Optional[int] = None,
             round: Optional[int] = None, **fields) -> None:
        self.logger.append(event, time=self.scheduler.now, node_id=self.node_id,
                           height=height, round=round, **fields)

    def _valid_transaction(self, tx: Transaction) -> bool:
        return (
            tx.chain_id == self.chain_id
            and verify_transaction_signature(tx)
        )

    @staticmethod
    def _tx_id(tx: Transaction) -> str:
        return sha256_hex(tx.canonical_bytes() + b"\x00" +
                          tx.signature.encode("ascii"))

    def _receive_transaction(self, envelope: NetworkEnvelope) -> None:
        try:
            tx = Transaction.from_dict(envelope.payload)
        except (KeyError, TypeError, ValueError):
            self._log("TX_REJECTED", height=self.height, round=self.round,
                      reason="malformed", peer_id=envelope.sender_id)
            return
        if not self._valid_transaction(tx):
            self._log("TX_REJECTED", height=self.height, round=self.round,
                      reason="invalid_signature_or_chain", peer_id=envelope.sender_id,
                      tx_id=self._tx_id(tx))
            return
        tx_id = self._tx_id(tx)
        if tx_id in self._committed_tx_ids:
            self._log("TX_DUPLICATE", height=self.height, round=self.round,
                      peer_id=envelope.sender_id, reason="already_committed",
                      tx_id=tx_id)
            return
        if tx_id in self.mempool:
            self._log("TX_DUPLICATE", height=self.height, round=self.round,
                      peer_id=envelope.sender_id, tx_id=tx_id)
            return
        self.mempool[tx_id] = tx
        self._log("TX_ACCEPTED", height=self.height, round=self.round,
                  peer_id=envelope.sender_id, tx_id=tx_id)
        # Re-gossip once. The transaction-ID guard stops loops and duplicate apply.
        recipients = tuple(peer for peer in self.network.peers(self.node_id)
                           if peer != envelope.sender_id)
        self.network.broadcast(self.node_id, tx.to_dict(), kind="TX",
                               height=self.height, recipients=recipients)

    def _validate_block(self, block: Block) -> bool:
        if block.chain_id != self.chain_id:
            return False
        if any(tx.chain_id != self.chain_id for tx in block.transactions):
            return False
        valid, _post, root, _results = execute_block(
            block, self.state, dry_run=True
        )
        return valid and root == block.state_root

    def _new_block(self) -> Tuple[Block, Optional[int], Tuple[Vote, ...]]:
        valid_round = self.engine.lock.valid_round
        valid_id = self.engine.lock.valid_block_id
        proof: Tuple[Vote, ...] = ()
        if valid_id and valid_round is not None:
            previous = self.engine.blocks.get(valid_id)
            polka = self.engine.polkas.get((self.height, valid_round, valid_id))
            if previous is not None and polka is not None:
                block = Block(
                    height=self.height,
                    round=self.round,
                    parent_id=self.engine.parent_id,
                    transactions=previous.transactions,
                    proposer_id=self.node_id,
                    timestamp=self.scheduler.now,
                    state_root=previous.state_root,
                    chain_id=self.chain_id,
                )
                proof = polka.votes
                return sign_block(block, self.private_key), valid_round, proof

        candidate = self.state.copy()
        chosen = []
        ordered = sorted(
            self.mempool.items(),
            key=lambda item: (item[1].sender, item[1].nonce, item[0]),
        )
        for _tx_id, tx in ordered:
            trial = candidate.copy()
            result = apply_transaction(tx, trial)
            if result.success:
                candidate = trial
                chosen.append(tx)
        block = Block(
            height=self.height,
            round=self.round,
            parent_id=self.engine.parent_id,
            transactions=tuple(chosen),
            proposer_id=self.node_id,
            timestamp=self.scheduler.now,
            state_root=candidate.state_root(),
            chain_id=self.chain_id,
        )
        return sign_block(block, self.private_key), None, ()

    def _maybe_propose(self) -> None:
        if self.selector.proposer_for(self.height, self.round) != self.node_id:
            return
        if (self.height, self.round) in self.silent_slots:
            self._log("PROPOSER_SILENT", height=self.height, round=self.round)
            return
        if self.engine.phase != Phase.PROPOSAL:
            return
        block, valid_round, proof = self._new_block()
        if (self.height, self.round) in self.equivocate_slots:
            self._equivocate_proposal(block, valid_round, proof)
            return
        if not self.engine.accept_proposal(block, valid_round, proof):
            self._log("PROPOSAL_REJECTED", height=self.height,
                      round=self.round, reason="local_validation_failed",
                      block_id=block.block_id)
            self._send_nil_prevote()
            return
        self._block_cache[block.block_id] = block
        self._proposal_seen[(block.height, block.round)] = block.block_id
        self._publish_proposal(block, valid_round, proof,
                               self.network.peers(self.node_id))
        self._cast_prevote(block.block_id)

    def _publish_proposal(self, block: Block, valid_round: Optional[int],
                          proof: Tuple[Vote, ...], recipients: Iterable[str]) -> None:
        body = {
            "block": block.to_dict(),
            "valid_round": valid_round,
            "prevote_proof": [vote.to_dict() for vote in proof],
        }
        proposal_id = self._proposal_id(block)
        body["proposal_id"] = proposal_id
        self._proposal_bodies[proposal_id] = body
        self._log("PROPOSAL_SENT", height=self.height, round=self.round,
                  block_id=block.block_id, tx_count=len(block.transactions),
                  state_root=block.state_root)
        header = {
            "block_id": block.block_id,
            "height": block.height,
            "round": block.round,
            "parent_id": block.parent_id,
            "proposer_id": block.proposer_id,
            "signature": block.signature,
            "state_root": block.state_root,
            "chain_id": block.chain_id,
            "valid_round": valid_round,
            "proposal_id": proposal_id,
        }
        self.network.announce_header(self.node_id, proposal_id, header,
                                     height=block.height,
                                     recipients=tuple(recipients))
        retry_delay = max(0.01, min(self.timer.config.base / 3.0,
                                    self.network.config.max_delay * 2.0))
        self.scheduler.schedule_after(
            retry_delay, self._retry_proposal_header,
            proposal_id, block.height, block.round, tuple(recipients), 1,
            tag="proposal-header-retry",
        )

    def _retry_proposal_header(self, proposal_id: str, height: int,
                               round_number: int, recipients: Tuple[str, ...],
                               attempt: int) -> None:
        if (self.height, self.round) != (height, round_number):
            return
        body = self._proposal_bodies.get(proposal_id)
        if body is None:
            return
        targets = tuple(peer for peer in recipients
                        if not self.network.gate.is_body_delivered(peer, proposal_id))
        if targets:
            block = Block.from_dict(body["block"])
            header = {
                "block_id": block.block_id,
                "height": block.height,
                "round": block.round,
                "parent_id": block.parent_id,
                "proposer_id": block.proposer_id,
                "signature": block.signature,
                "state_root": block.state_root,
                "chain_id": block.chain_id,
                "valid_round": body.get("valid_round"),
                "proposal_id": proposal_id,
            }
            self._log("PROPOSAL_HEADER_RETRY", height=height,
                      round=round_number, proposal_id=proposal_id,
                      attempt=attempt, recipients=len(targets))
            self.network.announce_header(
                self.node_id, proposal_id, header,
                height=height, recipients=targets,
            )
        if attempt < 3:
            retry_delay = max(0.01, min(self.timer.config.base / 3.0,
                                        self.network.config.max_delay * 2.0))
            self.scheduler.schedule_after(
                retry_delay, self._retry_proposal_header,
                proposal_id, height, round_number, recipients, attempt + 1,
                tag="proposal-header-retry",
            )

    def _equivocate_proposal(self, first: Block,
                             valid_round: Optional[int],
                             proof: Tuple[Vote, ...]) -> None:
        """Test-only Byzantine leader: send two valid values to two peer sets."""
        if not first.transactions:
            self._log("EQUIVOCATION_SKIPPED", height=self.height,
                      round=self.round, reason="needs_two_valid_values")
            self._proposal_seen[(first.height, first.round)] = first.block_id
            if self.engine.accept_proposal(first, valid_round, proof):
                self._block_cache[first.block_id] = first
                self._publish_proposal(first, valid_round, proof,
                                       self.network.peers(self.node_id))
                self._cast_prevote(first.block_id)
            return
        alternate_txs = first.transactions[:-1]
        alternate_template = Block(
            height=first.height,
            round=first.round,
            parent_id=first.parent_id,
            transactions=alternate_txs,
            proposer_id=self.node_id,
            timestamp=first.timestamp,
            state_root=self._root_after(alternate_txs),
            chain_id=self.chain_id,
        )
        second = sign_block(alternate_template, self.private_key)
        if second.block_id == first.block_id:
            return
        peers = self.network.peers(self.node_id)
        group_a = peers[::2]
        group_b = peers[1::2]
        if not group_b:
            group_b = group_a[-1:]
            group_a = group_a[:-1]
        if not self.engine.accept_proposal(first, valid_round, proof):
            self._log("PROPOSAL_REJECTED", height=self.height,
                      round=self.round, reason="equivocation_setup_invalid")
            return
        self._block_cache[first.block_id] = first
        self._block_cache[second.block_id] = second
        self._proposal_seen[(first.height, first.round)] = first.block_id
        self._publish_proposal(first, valid_round, proof, group_a)
        self._publish_proposal(second, None, (), group_b)
        self._cast_prevote(first.block_id, recipients=group_a)
        conflicting = sign_vote(
            Vote(first.height, first.round, Phase.PREVOTE, second.block_id,
                 self.node_id, chain_id=self.chain_id),
            self.private_key,
        )
        self._log("BYZANTINE_EQUIVOCATION", height=first.height,
                  round=first.round, phase=Phase.PREVOTE.value,
                  first_block=first.block_id, second_block=second.block_id)
        self._broadcast_vote(conflicting, recipients=group_b)

    def _root_after(self, transactions: Iterable[Transaction]) -> str:
        candidate = self.state.copy()
        for tx in transactions:
            result = apply_transaction(tx, candidate)
            if not result.success:
                return "invalid"
        return candidate.state_root()

    def _receive_header(self, envelope: NetworkEnvelope) -> None:
        payload = envelope.payload if isinstance(envelope.payload, dict) else {}
        try:
            block_id = str(payload["block_id"])
            proposal_id = str(payload["proposal_id"])
            height = int(payload["height"])
            round_number = int(payload["round"])
            proposer_id = str(payload["proposer_id"])
            chain_id = str(payload["chain_id"])
            signature = str(payload["signature"])
            state_root = str(payload["state_root"])
            parent_id = str(payload["parent_id"])
        except (KeyError, TypeError, ValueError):
            self._log("HEADER_REJECTED", height=self.height, round=self.round,
                      peer_id=envelope.sender_id, reason="malformed")
            return
        public_key = self.validator_public_keys.get(proposer_id)
        header_block = Block(
            height=height, round=round_number, parent_id=parent_id,
            proposer_id=proposer_id, block_id=block_id, signature=signature,
            state_root=state_root, chain_id=chain_id,
        )
        if (
            envelope.header_id != proposal_id
            or envelope.sender_id != proposer_id
            or chain_id != self.chain_id
            or height != self.height
            or round_number < self.round
            or round_number > self.round + 1
            or proposer_id != self.selector.proposer_for(height, round_number)
            or not public_key
            or not self._verify_header_signature(header_block, public_key)
        ):
            self._log("HEADER_REJECTED", height=height, round=round_number,
                      peer_id=envelope.sender_id, reason="invalid_header",
                      block_id=block_id)
            return
        if self.network.accept_header(self.node_id, proposal_id):
            self._log("HEADER_ACCEPTED", height=height, round=round_number,
                      peer_id=envelope.sender_id, block_id=block_id)
            self.network.request_body(self.node_id, envelope.sender_id, proposal_id,
                                      height=height)

    @staticmethod
    def _verify_header_signature(block: Block, public_key: str) -> bool:
        from src.crypto import verify_block_signature
        return verify_block_signature(block, public_key)

    def _receive_body_request(self, envelope: NetworkEnvelope) -> None:
        proposal_id = envelope.header_id
        body = self._proposal_bodies.get(proposal_id)
        if body is None:
            self._log("BODY_REQUEST_REJECTED", height=self.height,
                      round=self.round, peer_id=envelope.sender_id,
                      proposal_id=proposal_id, reason="unknown_header")
            return
        self.network.send_body(self.node_id, envelope.sender_id, proposal_id, body,
                               height=self.height)

    def _receive_body(self, envelope: NetworkEnvelope) -> None:
        body = envelope.payload if isinstance(envelope.payload, dict) else {}
        try:
            block = Block.from_dict(body["block"])
            proposal_id = str(body["proposal_id"])
            valid_round = body.get("valid_round")
            valid_round = None if valid_round is None else int(valid_round)
            proof = tuple(Vote.from_dict(v) for v in body.get("prevote_proof", []))
        except (KeyError, TypeError, ValueError):
            self._log("PROPOSAL_REJECTED", height=self.height,
                      round=self.round, peer_id=envelope.sender_id,
                      reason="malformed_body")
            return
        if proposal_id in self._seen_bodies:
            self._log("BODY_DUPLICATE", height=block.height, round=block.round,
                      peer_id=envelope.sender_id, block_id=block.block_id)
            return
        if envelope.sender_id != block.proposer_id or envelope.header_id != proposal_id:
            self._log("PROPOSAL_REJECTED", height=block.height,
                      round=block.round, peer_id=envelope.sender_id,
                      reason="body_header_mismatch", block_id=block.block_id)
            return
        slot = (block.height, block.round)
        previous_proposal = self._proposal_seen.get(slot)
        if previous_proposal is not None and previous_proposal != block.block_id:
            self._log("PROPOSER_EQUIVOCATION_REJECTED", height=block.height,
                      round=block.round, peer_id=envelope.sender_id,
                      first_block=previous_proposal, second_block=block.block_id)
            return
        evidence_before = self._consensus_snapshot()
        old_round = self.round
        if not self.engine.accept_proposal(block, valid_round, proof):
            self._log("PROPOSAL_REJECTED", height=block.height,
                      round=block.round, peer_id=envelope.sender_id,
                      reason="validation_failed", block_id=block.block_id)
            return
        if self.round != old_round:
            self.timer.stop()
            self.timer.start(self.height, self.round)
            self._log("ROUND_SYNC", height=self.height, round=self.round,
                      source="valid_proposal")
        self._seen_bodies.add(proposal_id)
        self._proposal_seen[slot] = block.block_id
        self._block_cache[block.block_id] = block
        self._log("PROPOSAL_ACCEPTED", height=block.height, round=block.round,
                  peer_id=envelope.sender_id, block_id=block.block_id,
                  state_root=block.state_root)
        if not self.engine.votes.has(self.height, self.round,
                                     Phase.PREVOTE, self.node_id):
            self._cast_prevote(block.block_id)
        vote, certificate = self.engine.process_pending_block(block.block_id)
        self._log_consensus_changes(evidence_before, block.height, block.round)
        if vote is not None:
            self._broadcast_vote(vote)
        if certificate is not None:
            self._finish_local_commit(certificate, block)
        if self.height == block.height:
            self._drain_future_votes(self.height, self.round)

    def _cast_prevote(self, block_id: str,
                      recipients: Optional[Iterable[str]] = None) -> None:
        try:
            vote = self.engine.make_prevote(block_id)
        except ValueError as exc:
            self._log("PREVOTE_REJECTED", height=self.height,
                      round=self.round, reason=str(exc), block_id=block_id)
            return
        self._broadcast_vote(vote, recipients=recipients)

    def _send_nil_prevote(self) -> None:
        if self.engine.votes.has(self.height, self.round,
                                 Phase.PREVOTE, self.node_id):
            return
        try:
            self._broadcast_vote(self.engine.make_prevote(NIL_BLOCK_ID))
        except ValueError:
            pass

    def _broadcast_vote(self, vote: Vote,
                        recipients: Optional[Iterable[str]] = None) -> None:
        proof = ()
        if vote.phase == Phase.PRECOMMIT and vote.block_id != NIL_BLOCK_ID:
            polka = self.engine.polkas.get((vote.height, vote.round,
                                            vote.block_id))
            proof = polka.votes if polka else ()
        payload = {
            "vote": vote.to_dict(),
            "prevote_proof": [item.to_dict() for item in proof],
        }
        self._log("VOTE_SENT", height=vote.height, round=vote.round,
                  phase=vote.phase.value, block_id=vote.block_id,
                  voter_id=vote.voter_id)
        self.network.broadcast(self.node_id, payload,
                              kind=vote.phase.value, height=vote.height,
                              recipients=(None if recipients is None else
                                          tuple(recipients)))

    def _receive_vote(self, envelope: NetworkEnvelope) -> None:
        try:
            payload = envelope.payload
            vote = Vote.from_dict(payload["vote"])
            proof = tuple(Vote.from_dict(v)
                          for v in payload.get("prevote_proof", []))
        except (KeyError, TypeError, ValueError, AttributeError):
            self._log("VOTE_REJECTED", height=self.height, round=self.round,
                      peer_id=envelope.sender_id, reason="malformed")
            return
        if envelope.sender_id != vote.voter_id or envelope.kind != vote.phase.value:
            self._log("VOTE_REJECTED", height=vote.height, round=vote.round,
                      peer_id=envelope.sender_id, voter_id=vote.voter_id,
                      reason="sender_or_phase_mismatch")
            return
        rejection = self.engine.vote_rejection_reason(vote)
        if rejection:
            self._log("VOTE_REJECTED", height=vote.height, round=vote.round,
                      peer_id=envelope.sender_id, voter_id=vote.voter_id,
                      phase=vote.phase.value, reason=rejection)
            return
        if vote.height == self.height and self.round < vote.round <= self.round + 1:
            self._future_votes.setdefault((vote.height, vote.round), []).append(
                (vote, proof, envelope.sender_id)
            )
            self._log("VOTE_BUFFERED", height=vote.height, round=vote.round,
                      peer_id=envelope.sender_id, voter_id=vote.voter_id,
                      phase=vote.phase.value, block_id=vote.block_id)
            return
        if vote.height != self.height or vote.round != self.round:
            self._log("VOTE_REJECTED", height=vote.height, round=vote.round,
                      peer_id=envelope.sender_id, voter_id=vote.voter_id,
                      phase=vote.phase.value, reason="stale_or_future_slot")
            return
        old_height, old_round = self.height, self.round
        evidence_before = self._consensus_snapshot()
        already_had_vote = self.engine.votes.has(
            vote.height, vote.round, vote.phase, vote.voter_id
        )
        effect = self.engine.receive_vote(vote, proof)
        self._log_consensus_changes(evidence_before, vote.height, vote.round)
        vote_was_accepted = (
            not already_had_vote
            and self.engine.votes.has(vote.height, vote.round,
                                      vote.phase, vote.voter_id)
        )
        if vote_was_accepted:
            self._log("VOTE_ACCEPTED", height=vote.height, round=vote.round,
                      peer_id=envelope.sender_id, voter_id=vote.voter_id,
                      phase=vote.phase.value, block_id=vote.block_id)
        elif isinstance(effect, FinalizeCertificate) and not already_had_vote:
            self._log("VOTE_ACCEPTED", height=vote.height, round=vote.round,
                      peer_id=envelope.sender_id, voter_id=vote.voter_id,
                      phase=vote.phase.value, block_id=vote.block_id)
        elif effect is None:
            previous = self.engine.votes.get(
                vote.height, vote.round, vote.phase, vote.voter_id
            )
            if previous is not None and previous.block_id != vote.block_id:
                self._log("VOTE_CONFLICT", height=vote.height, round=vote.round,
                          peer_id=envelope.sender_id, voter_id=vote.voter_id,
                          phase=vote.phase.value,
                          first_block=previous.block_id,
                          block_id=vote.block_id)
            elif previous is not None:
                self._log("VOTE_DUPLICATE", height=vote.height, round=vote.round,
                          peer_id=envelope.sender_id, voter_id=vote.voter_id,
                          phase=vote.phase.value, block_id=vote.block_id)
            elif (vote.phase == Phase.PRECOMMIT and
                  vote.block_id != NIL_BLOCK_ID and
                  (vote.height, vote.round, vote.block_id) not in self.engine.polkas):
                self._log("VOTE_REJECTED", height=vote.height, round=vote.round,
                          peer_id=envelope.sender_id, voter_id=vote.voter_id,
                          phase=vote.phase.value, reason="missing_polka")
            elif vote.height != old_height or vote.round != old_round:
                self._log("VOTE_REJECTED", height=vote.height, round=vote.round,
                          peer_id=envelope.sender_id, voter_id=vote.voter_id,
                          reason="stale_or_future_slot")
        if isinstance(effect, Vote):
            self._broadcast_vote(effect)
        elif isinstance(effect, FinalizeCertificate):
            block = self._block_cache.get(effect.block_id)
            if block is not None:
                self._finish_local_commit(effect, block)
        if self.height != old_height:
            if not isinstance(effect, FinalizeCertificate):
                self._after_height_change()
        elif self.round != old_round:
            self._after_round_change()

    def _receive_finalize(self, envelope: NetworkEnvelope) -> None:
        try:
            certificate = FinalizeCertificate.from_dict(envelope.payload["certificate"])
            block = Block.from_dict(envelope.payload["block"])
        except (KeyError, TypeError, ValueError, AttributeError):
            self._log("FINALIZE_REJECTED", height=self.height, round=self.round,
                      peer_id=envelope.sender_id, reason="malformed")
            return
        if envelope.sender_id not in self.validators:
            self._log("FINALIZE_REJECTED", height=certificate.height,
                      round=certificate.round, peer_id=envelope.sender_id,
                      reason="unknown_sender")
            return
        if certificate.height > self.height:
            previous = self._pending_certificates.get(certificate.height)
            if previous is not None and previous[1].block_id != block.block_id:
                self._log("FINALIZE_CONFLICT_REJECTED", height=certificate.height,
                          round=certificate.round, peer_id=envelope.sender_id,
                          block_id=block.block_id,
                          existing_block=previous[1].block_id)
                return
            self._pending_certificates[certificate.height] = (certificate, block)
            self._log("FINALIZE_BUFFERED", height=certificate.height,
                      round=certificate.round, peer_id=envelope.sender_id,
                      block_id=block.block_id)
            return
        if certificate.height < self.height:
            existing = next((b for b in self.ledger
                             if b.height == certificate.height), None)
            event = "FINALIZE_DUPLICATE" if existing and existing.block_id == block.block_id else "FINALIZE_CONFLICT_REJECTED"
            self._log(event, height=certificate.height, round=certificate.round,
                      peer_id=envelope.sender_id, block_id=block.block_id)
            return
        old_height = self.height
        if not self.engine.commit_certificate(certificate, block):
            self._log("FINALIZE_REJECTED", height=certificate.height,
                      round=certificate.round, peer_id=envelope.sender_id,
                      reason="invalid_certificate", block_id=block.block_id)
            return
        self._block_cache[block.block_id] = block
        self._apply_committed_block(block, certificate, source=envelope.sender_id,
                                    rebroadcast=False)
        if self.height != old_height:
            self._after_height_change()

    def _receive_finalize_pending(self) -> None:
        pending = self._pending_certificates.pop(self.height, None)
        if pending is None:
            return
        certificate, block = pending
        if self.engine.commit_certificate(certificate, block):
            self._apply_committed_block(block, certificate, source="buffer",
                                        rebroadcast=False)
            self._after_height_change()
        else:
            self._log("FINALIZE_REJECTED", height=certificate.height,
                      round=certificate.round, source="buffer",
                      reason="invalid_certificate", block_id=block.block_id)

    def _finish_local_commit(self, certificate: FinalizeCertificate,
                             block: Block) -> None:
        self._apply_committed_block(block, certificate, source=self.node_id,
                                    rebroadcast=True)
        self._after_height_change()

    def _proposal_id(self, block: Block) -> str:
        context = (f"{block.chain_id}:{block.height}:{block.round}:"
                   f"{block.proposer_id}:{block.block_id}")
        return sha256_hex(context.encode("utf-8"))

    def _consensus_snapshot(self) -> tuple:
        return (
            self.engine.lock.locked_block_id,
            self.engine.lock.locked_round,
            self.engine.lock.valid_block_id,
            self.engine.lock.valid_round,
            frozenset(self.engine.polkas),
        )

    def _log_consensus_changes(self, before: tuple, height: int,
                               round_number: int) -> None:
        after = self._consensus_snapshot()
        for key in sorted(after[4] - before[4]):
            polka = self.engine.polkas[key]
            self._log("POLKA_OBSERVED", height=height, round=round_number,
                      polka_round=polka.round, block_id=polka.block_id,
                      vote_count=len(polka.votes))
        if (before[0], before[1]) != (after[0], after[1]):
            self._log("LOCK_CHANGED", height=height, round=round_number,
                      locked_block_id=after[0], locked_round=after[1])
        if (before[2], before[3]) != (after[2], after[3]):
            self._log("VALID_ROUND_UPDATED", height=height, round=round_number,
                      valid_block_id=after[2], valid_round=after[3])

    def _apply_committed_block(self, block: Block,
                               certificate: FinalizeCertificate,
                               *, source: str, rebroadcast: bool) -> None:
        existing = next((item for item in self.ledger
                         if item.height == block.height), None)
        if existing is not None:
            if existing.block_id != block.block_id:
                self._log("SAFETY_VIOLATION", height=block.height,
                          round=certificate.round, source=source,
                          existing_block=existing.block_id,
                          conflicting_block=block.block_id)
            return
        valid, post_state, root, _results = execute_block(block, self.state)
        if not valid or root != block.state_root:
            self._log("EXECUTION_COMMIT_REJECTED", height=block.height,
                      round=certificate.round, source=source,
                      block_id=block.block_id, computed_root=root)
            return
        self.state = post_state
        self.ledger.append(block)
        self.state_roots[block.height] = root
        self._block_cache[block.block_id] = block
        committed_ids = {self._tx_id(tx) for tx in block.transactions}
        self._committed_tx_ids.update(committed_ids)
        for tx_id in committed_ids:
            self.mempool.pop(tx_id, None)
        for tx_id, tx in tuple(self.mempool.items()):
            account = self.state.accounts.get(tx.sender)
            current_nonce = account.nonce if account is not None else 0
            if tx.nonce < current_nonce:
                self.mempool.pop(tx_id, None)
        self._log("BLOCK_FINALIZED", height=block.height,
                  round=certificate.round, source=source,
                  block_id=block.block_id, state_root=root,
                  tx_count=len(block.transactions))
        self.timer.stop()
        if rebroadcast:
            payload = {"certificate": certificate.to_dict(),
                       "block": block.to_dict()}
            self.network.broadcast(self.node_id, payload, kind="FINALIZE",
                                   height=block.height)

    def _after_height_change(self) -> None:
        self.timer.stop()
        self._log("HEIGHT_CHANGE", height=self.height, round=self.round,
                  parent_id=self.engine.parent_id)
        self._receive_finalize_pending()
        if self.timer.active_slot is None:
            self._enter_round()

    def _after_round_change(self) -> None:
        self.timer.stop()
        self._log("ROUND_CHANGE", height=self.height, round=self.round)
        self._enter_round()
        self._drain_future_votes(self.height, self.round)

    def _drain_future_votes(self, height: int, round_number: int) -> None:
        buffered = self._future_votes.pop((height, round_number), [])
        for index, (vote, proof, source) in enumerate(buffered, start=1):
            envelope = NetworkEnvelope(
                envelope_id=f"buffered-{height}-{round_number}-{index}",
                kind=vote.phase.value,
                sender_id=source,
                recipient_id=self.node_id,
                payload={"vote": vote.to_dict(),
                         "prevote_proof": [item.to_dict() for item in proof]},
                send_time=self.scheduler.now,
                deliver_time=self.scheduler.now,
                height=height,
            )
            self._receive_vote(envelope)

    def _enter_round(self) -> None:
        if self.timer.active_slot != (self.height, self.round):
            self.timer.start(self.height, self.round)
        self._maybe_propose()

    def _on_timeout(self, height: int, round_number: int) -> None:
        if (height, round_number) != (self.height, self.round):
            return
        self._log("ROUND_TIMEOUT", height=height, round=round_number)
        self._send_nil_prevote()
        if not self.engine.votes.has(height, round_number,
                                     Phase.PRECOMMIT, self.node_id):
            try:
                self._broadcast_vote(self.engine.make_precommit(NIL_BLOCK_ID))
            except ValueError:
                pass
        if self.engine.on_timeout(height, round_number):
            self._log("ROUND_CHANGE", height=self.height, round=self.round,
                      reason="timeout")
            self._enter_round()

