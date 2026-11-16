"""One signed validator, integrating consensus, execution and simulated P2P.

Blocks keep their original creation round. A separately signed proposal header
names the current round/leader and carries the polka when re-proposing a block.
All block transfers (including catch-up) use HEADER -> BODY_REQUEST -> BODY.
Transactions are supplied by the application; transaction gossip is not modeled.
"""

from __future__ import annotations

import math
from typing import Callable, Dict, Iterable, Optional

from src.consensus.engine import ConsensusEngine
from src.consensus.locking import Polka
from src.consensus.proposer import ProposerSelector
from src.consensus.timeout import TimeoutConfig, TimeoutManager
from src.crypto import (
    public_key_from_private, sha256_hex, sign, sign_block, sign_vote,
    verify, verify_transaction_signature, verify_vote_signature,
)
from src.execution import BlockValidator, WorldState, apply_transaction, execute_block
from src.models import (
    Block, FinalizeCertificate, NIL_BLOCK_ID, Phase, Transaction, Vote,
    _canonical_json, genesis_block,
)
from src.network import KIND_BODY, KIND_BODY_REQUEST, KIND_HEADER, Network, NetworkEnvelope
from src.scheduler import Scheduler


class Node:
    """A validator with independent committed state and cancellable timers.

    ``public_keys`` maps logical validator IDs to Ed25519 keys. Event callbacks
    receive JSON-ready dictionaries and must not use wall-clock randomness.
    ``silent_proposer`` suppresses proposals, but still permits voting/sync.
    Gossip is paced to reserve half the configured link rate for live traffic;
    ``gossip_interval`` is a requested minimum, not an unconditional send rate.
    """

    def __init__(
        self, node_id: str, validators: Iterable[str], scheduler: Scheduler,
        network: Network, private_key: str, public_keys: Dict[str, str],
        genesis_state: WorldState, *, proposer_selector: Optional[ProposerSelector] = None,
        timeout_config: Optional[TimeoutConfig] = None, gossip_interval: float = 0.25,
        max_transactions: int = 100, max_pending: int = 4096,
        event_sink: Optional[Callable[[dict], None]] = None,
        silent_proposer: bool = False,
    ) -> None:
        validators = tuple(validators)
        if node_id not in validators or set(validators) != set(public_keys):
            raise ValueError("node and public keys must match the validator set")
        if set(network.nodes) != set(validators) or scheduler is not network.scheduler:
            raise ValueError("node must use the network's scheduler and validator topology")
        if public_key_from_private(private_key) != public_keys[node_id]:
            raise ValueError("private key does not match node's public key")
        if (not math.isfinite(gossip_interval) or gossip_interval <= 0
                or type(max_transactions) is not int or max_transactions < 1
                or type(max_pending) is not int or max_pending < 1):
            raise ValueError("gossip interval and capacities must be positive")
        self.node_id, self.validators = node_id, validators
        self.scheduler, self.network = scheduler, network
        self.private_key, self.public_keys = private_key, dict(public_keys)
        self.world_state = genesis_state.copy()
        genesis = genesis_block()
        self.chain: Dict[int, Block] = {0: genesis}
        self.certificates: Dict[int, FinalizeCertificate] = {}
        self.blocks: Dict[str, Block] = {genesis.block_id: genesis}
        self.mempool: Dict[str, Transaction] = {}
        self.events: list[dict] = []
        self._event_sink = event_sink
        policy = network.config.rate_limit
        # Reserve half of each link's sustained allowance for handshakes and
        # live consensus traffic. A gossip cycle sends at most five adverts.
        allowance = min(policy.refill_per_second, policy.inbound_capacity / policy.inbound_window)
        self.gossip_interval = max(gossip_interval, 10.0 / allowance)
        self.max_transactions = max_transactions
        self.max_pending = max_pending
        self.selector = proposer_selector or ProposerSelector(validators)
        if self.selector.validators != validators:
            raise ValueError("proposer selector must use the same ordered validators")
        self.block_validator = BlockValidator(
            lambda: self.world_state, public_key_resolver=self.public_keys.__getitem__,
            proposer_resolver=self.selector.proposer_for, require_state_root=True,
        )
        self.engine = ConsensusEngine(
            node_id, validators, parent=genesis,
            proposer_selector=self.selector, require_signatures=True,
            block_validator=self.block_validator,
            public_key_resolver=self.public_keys.__getitem__,
            vote_signer=lambda vote: sign_vote(vote, self.private_key),
        )
        self.timeout_manager = TimeoutManager(scheduler, self.on_timeout, timeout_config)
        self.running = False
        self.crashed = False
        self.silent_proposer = silent_proposer
        self._gossip_handle = None
        self._round_handle = None
        self._outgoing: Dict[str, tuple[dict, Block]] = {}
        self._headers: Dict[str, dict] = {}
        self._received_bodies: set[str] = set()
        self._proposals: Dict[tuple, tuple[dict, Block]] = {}
        self._pending_votes: Dict[tuple, Vote] = {}
        self._pending_finalizations: Dict[int, tuple[Block, FinalizeCertificate]] = {}
        self._known_polkas: Dict[tuple, Polka] = {}
        self._announced_polkas: set[tuple] = set()
        self._proposed_slots: set[tuple] = set()
        self.network.set_receiver(node_id, self.on_receive)

    @property
    def committed_height(self) -> int:
        return max(self.chain)

    def _log(self, event: str, **details) -> None:
        record = {"time": self.scheduler.now, "node_id": self.node_id,
                  "event": event, "height": self.engine.height,
                  "round": self.engine.round, **details}
        self.events.append(record)
        if self._event_sink:
            self._event_sink(dict(record))

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        self._schedule_round()
        self._schedule_gossip()

    def stop(self) -> None:
        self.running = False
        self.timeout_manager.stop()
        self.scheduler.cancel(self._gossip_handle)
        self.scheduler.cancel(self._round_handle)

    def crash(self) -> None:
        self.crashed = True
        self.timeout_manager.stop()
        self.scheduler.cancel(self._gossip_handle)
        self.scheduler.cancel(self._round_handle)
        self._log("CRASH")

    def recover(self) -> None:
        if not self.crashed:
            return
        self.crashed = False
        self._log("RECOVER")
        if self.running:
            self._schedule_round()
            self._schedule_gossip()
            self._request_sync()

    def _schedule_round(self) -> None:
        self.scheduler.cancel(self._round_handle)
        self._round_handle = self.scheduler.schedule_after(0, self.enter_round, tag="enter-round")

    def enter_round(self) -> None:
        if not self.running or self.crashed:
            return
        self.timeout_manager.start(self.engine.height, self.engine.round)
        self._log("ENTER_ROUND")
        self._drain_pending()
        if self.selector.is_proposer(self.node_id, self.engine.height, self.engine.round):
            self.propose_block()

    def on_timeout(self, height: int, round: int) -> None:
        if self.running and not self.crashed and self.engine.on_timeout(height, round):
            self._log("TIMEOUT", expired_height=height, expired_round=round)
            self._schedule_round()

    def submit_transaction(self, tx: Transaction) -> bool:
        """Admit signed transactions; balance/nonce are checked when building a block.

        Future nonces are allowed in the pool, so a transaction may become
        executable after an earlier transaction is committed.
        """
        if (not isinstance(tx, Transaction) or type(tx.amount) is not int or type(tx.nonce) is not int
                or tx.amount < 0 or tx.nonce < 0 or not tx.receiver
                or not verify_transaction_signature(tx)):
            return False
        key = sha256_hex(_canonical_json(tx.to_dict()))
        if key in self.mempool:
            return False
        self.mempool[key] = tx
        self._log("TX_ADMITTED", tx_id=key)
        return True

    def propose_block(self) -> Optional[Block]:
        slot = (self.engine.height, self.engine.round)
        if (not self.running or self.crashed or self.silent_proposer
                or not self.selector.is_proposer(self.node_id, *slot)
                or slot in self._proposed_slots):
            return None
        self._proposed_slots.add(slot)
        proofs = [p for p in self._known_polkas.values()
                  if p.height == slot[0] and p.round < slot[1] and p.block_id in self.blocks]
        proof = max(proofs, key=lambda p: (p.round, p.block_id), default=None)
        if proof:
            block = self.blocks[proof.block_id]
        else:
            work = self.world_state.copy()
            transactions = []
            # Insertion order is part of this simulator's workload contract.
            for tx in self.mempool.values():
                candidate = work.copy()
                if apply_transaction(tx, candidate).success:
                    work = candidate
                    transactions.append(tx)
                    if len(transactions) >= self.max_transactions:
                        break
            block = sign_block(Block(
                height=slot[0], round=slot[1], parent_id=self.engine.parent_id,
                transactions=tuple(transactions), proposer_id=self.node_id,
                timestamp=self.scheduler.now, state_root=work.state_root(),
            ), self.private_key)
        header = self._make_header("PROPOSAL", block, slot[1], polka=proof)
        self._announce(header, block)
        self._log("PROPOSE", block_id=block.block_id)
        self._handle_proposal(header, block)
        return block

    @staticmethod
    def _polka_dict(polka: Polka) -> dict:
        return {"height": polka.height, "round": polka.round, "block_id": polka.block_id,
                "votes": [v.to_dict() for v in polka.votes]}

    @staticmethod
    def _parse_polka(data: dict) -> Polka:
        return Polka(int(data["height"]), int(data["round"]), data["block_id"],
                     tuple(Vote.from_dict(v) for v in data["votes"]))

    def _signed(self, data: dict) -> dict:
        return {**data, "signature": sign(_canonical_json(data), self.private_key)}

    def _authentic(self, data: dict, sender: str) -> bool:
        return (sender in self.public_keys and data.get("sender_id") == sender
                and verify(_canonical_json({k: v for k, v in data.items() if k != "signature"}),
                           data.get("signature", ""), self.public_keys[sender]))

    def _make_header(self, purpose: str, block: Block, round_: int, *,
                     polka: Optional[Polka] = None,
                     certificate: Optional[FinalizeCertificate] = None) -> dict:
        return self._signed({
            "purpose": purpose, "height": block.height, "round": round_,
            "sender_id": self.node_id, "block_id": block.block_id,
            "polka": self._polka_dict(polka) if polka else None,
            "certificate": certificate.to_dict() if certificate else None,
        })

    def _announce(self, header: dict, block: Block, recipients=None) -> None:
        header_id = sha256_hex(_canonical_json(header))
        self._outgoing[header_id] = (header, block)
        self.network.announce_header(self.node_id, header_id, header,
                                     height=block.height, recipients=recipients)

    def _broadcast_vote(self, vote: Vote) -> None:
        self._log("VOTE", phase=vote.phase.value, block_id=vote.block_id)
        self.network.broadcast(self.node_id, vote.to_dict(), kind=vote.phase.value, height=vote.height)

    def _handle_proposal(self, header: dict, block: Block) -> None:
        slot = (header["height"], header["round"])
        if slot != (self.engine.height, self.engine.round):
            if slot[0] > self.engine.height or (slot[0] == self.engine.height and slot[1] > self.engine.round):
                if len(self._proposals) < self.max_pending:
                    self._proposals[(*slot, header["sender_id"])] = (header, block)
            return
        if self.engine.vote_pool.has(*slot, Phase.PREVOTE, self.node_id):
            return
        proof = self._parse_polka(header["polka"]) if header["polka"] else None
        if not self.engine.accept_proposal(
            block, proposal_round=slot[1], proposer_id=header["sender_id"], valid_round_polka=proof,
        ):
            self._log("REJECT_PROPOSAL", block_id=block.block_id)
            candidate = self.engine.lock.locked_block_id or NIL_BLOCK_ID
        else:
            self.blocks[block.block_id] = block
            if proof:
                self._remember_polka(proof, block)
            candidate = block.block_id
        self._broadcast_vote(self.engine.make_prevote(candidate))
        self._after_votes()

    def _handle_vote(self, vote: Vote) -> None:
        if vote.height < self.engine.height or (vote.height == self.engine.height and vote.round < self.engine.round):
            return
        if ((vote.height, vote.round) != (self.engine.height, self.engine.round)
                or (vote.block_id != NIL_BLOCK_ID and vote.block_id not in self.engine.blocks)):
            key = (vote.height, vote.round, vote.phase, vote.voter_id)
            if len(self._pending_votes) < self.max_pending:
                self._pending_votes.setdefault(key, vote)
            return
        old_slot = (self.engine.height, self.engine.round)
        action = self.engine.receive_vote(vote)
        self._process_action(action)
        self._after_votes()
        if (self.engine.height, self.engine.round) != old_slot:
            self._schedule_round()

    def _process_action(self, action) -> None:
        if isinstance(action, Vote):
            self._broadcast_vote(action)
        elif isinstance(action, FinalizeCertificate):
            self.commit_finalized_block(self.blocks[action.block_id], action)

    def _remember_polka(self, proof: Polka, block: Block) -> None:
        if (not self.engine.verify_polka(proof) or proof.height != block.height
                or proof.block_id != block.block_id or proof.round < block.round):
            return
        self.blocks[block.block_id] = block
        self._known_polkas[(proof.height, proof.round, proof.block_id)] = proof

    def _after_votes(self) -> None:
        for action in self.engine.poll():
            self._process_action(action)
        for key, proof in tuple(self.engine.polkas.items()):
            block = self.blocks.get(proof.block_id)
            if block:
                self._remember_polka(proof, block)
                if key not in self._announced_polkas:
                    self._announced_polkas.add(key)
                    self._announce(self._make_header("VALID", block, proof.round, polka=proof), block)

    def commit_finalized_block(self, block: Block, certificate: FinalizeCertificate) -> bool:
        """Commit exactly once; accepts a certificate from a different round."""
        if block.height < 1:
            return False
        if block.height <= self.committed_height:
            if self.chain[block.height].block_id != block.block_id:
                self._log("REJECT_FINALIZE", reason="conflicting committed block")
            return False
        if (certificate.height != block.height or certificate.block_id != block.block_id
                or block.round < 0 or certificate.round < block.round
                or block.proposer_id not in self.public_keys
                or not self.engine.verify_certificate(certificate)):
            return False
        if block.height != self.committed_height + 1:
            if len(self._pending_finalizations) < self.max_pending:
                self._pending_finalizations.setdefault(block.height, (block, certificate))
            return False
        if not self.block_validator.validate(block, self.chain[self.committed_height]):
            self._log("REJECT_FINALIZE", reason=self.block_validator.last_result.error)
            return False
        if self.engine.height == block.height:
            if not self.engine.accept_finalize(block, certificate):
                return False
        elif self.engine.finalized.get(block.height) != certificate:
            return False
        valid, post_state, root, _ = execute_block(block, self.world_state, dry_run=True)
        if not valid or root != block.state_root:
            raise RuntimeError("validated block failed deterministic execution")
        self.timeout_manager.stop()
        self.chain[block.height], self.certificates[block.height] = block, certificate
        self.blocks[block.block_id] = block
        self.world_state = post_state
        included = {sha256_hex(_canonical_json(tx.to_dict())) for tx in block.transactions}
        self.mempool = {key: tx for key, tx in self.mempool.items() if key not in included
                        and (tx.sender not in self.world_state.accounts
                             or tx.nonce >= self.world_state.accounts[tx.sender].nonce)}
        self._log("COMMIT", height=block.height, round=certificate.round,
                  block_id=block.block_id, state_root=root)
        self._announce(self._make_header("FINALIZE", block, certificate.round, certificate=certificate), block)
        self._pending_votes = {k: v for k, v in self._pending_votes.items() if k[0] > block.height}
        self._proposals = {k: v for k, v in self._proposals.items() if k[0] > block.height}
        self._known_polkas = {k: v for k, v in self._known_polkas.items() if k[0] > block.height}
        self._schedule_round()
        return True

    def _drain_pending(self) -> None:
        while self.committed_height + 1 in self._pending_finalizations:
            block, certificate = self._pending_finalizations.pop(self.committed_height + 1)
            if not self.commit_finalized_block(block, certificate):
                break
        slot = (self.engine.height, self.engine.round)
        for key, (header, block) in tuple(self._proposals.items()):
            if key[:2] == slot:
                self._proposals.pop(key, None)
                self._handle_proposal(header, block)
        for key, vote in tuple(self._pending_votes.items()):
            if (key[:2] == (self.engine.height, self.engine.round)
                    and (vote.block_id == NIL_BLOCK_ID or vote.block_id in self.engine.blocks)):
                self._pending_votes.pop(key, None)
                self._handle_vote(vote)

    def on_receive(self, node_id: str, envelope: NetworkEnvelope) -> None:
        if not self.running or self.crashed or node_id != self.node_id:
            return
        if envelope.recipient_id != self.node_id or envelope.sender_id not in self.public_keys:
            return
        try:
            self._dispatch(envelope)
        except (KeyError, TypeError, ValueError, AttributeError, OverflowError) as exc:
            self._log("REJECT_MESSAGE", kind=envelope.kind, reason=str(exc))

    def _dispatch(self, envelope: NetworkEnvelope) -> None:
        data, sender, kind = envelope.payload, envelope.sender_id, envelope.kind
        if not isinstance(data, dict):
            raise ValueError("payload must be a dictionary")
        if kind in (Phase.PREVOTE.value, Phase.PRECOMMIT.value):
            vote = Vote.from_dict(data)
            if (vote.voter_id != sender or vote.phase.value != kind
                    or vote.height != envelope.height or vote.round < 0
                    or vote.height > self.engine.height + 32
                    or vote.round > self.engine.round + 64
                    or not verify_vote_signature(vote, self.public_keys[sender])):
                raise ValueError("invalid vote envelope or signature")
            self._handle_vote(vote)
        elif kind == KIND_HEADER:
            if (not self._authentic(data, sender)
                    or sha256_hex(_canonical_json(data)) != envelope.header_id
                    or type(data["height"]) is not int or type(data["round"]) is not int
                    or data["height"] != envelope.height or data["height"] < self.engine.height
                    or data["height"] > self.engine.height + 32 or data["round"] < 0):
                raise ValueError("invalid or stale header")
            purpose = data["purpose"]
            if purpose == "PROPOSAL":
                if (self.selector.proposer_for(data["height"], data["round"]) != sender
                        or data["round"] > self.engine.round + 64):
                    raise ValueError("wrong proposer or distant round")
            elif purpose == "FINALIZE":
                certificate = FinalizeCertificate.from_dict(data["certificate"])
                if ((certificate.height, certificate.round, certificate.block_id)
                        != (data["height"], data["round"], data["block_id"])
                        or not self.engine.verify_certificate(certificate)):
                    raise ValueError("invalid finalize certificate")
            elif purpose == "VALID":
                proof = self._parse_polka(data["polka"])
                if ((proof.height, proof.round, proof.block_id)
                        != (data["height"], data["round"], data["block_id"])
                        or not self.engine.verify_polka(proof)):
                    raise ValueError("invalid polka")
            else:
                raise ValueError("unknown header purpose")
            if len(self._headers) >= self.max_pending and envelope.header_id not in self._headers:
                self._headers = {k: h for k, h in self._headers.items() if h["height"] >= self.engine.height}
                if len(self._headers) >= self.max_pending:
                    return
            self._headers[envelope.header_id] = dict(data)
            if self.network.accept_header(self.node_id, envelope.header_id):
                if envelope.header_id not in self._received_bodies:
                    self.network.request_body(self.node_id, sender, envelope.header_id, height=data["height"])
        elif kind == KIND_BODY_REQUEST:
            entry = self._outgoing.get(envelope.header_id)
            if entry:
                header, block = entry
                self.network.send_body(self.node_id, sender, envelope.header_id,
                                       {"block": block.to_dict()}, height=header["height"])
        elif kind == KIND_BODY:
            header = self._headers.get(envelope.header_id)
            if not header or header["sender_id"] != sender or envelope.header_id in self._received_bodies:
                return
            block = Block.from_dict(data["block"])
            if (block.block_id != header["block_id"] or block.height != header["height"]
                    or envelope.height != block.height):
                raise ValueError("body does not match accepted header")
            if block.height < self.engine.height:
                return
            self._received_bodies.add(envelope.header_id)
            if header["purpose"] == "FINALIZE":
                self.commit_finalized_block(block, FinalizeCertificate.from_dict(header["certificate"]))
            elif header["purpose"] == "VALID":
                if block.height == self.engine.height and self.block_validator.validate(
                    block, self.chain[self.committed_height]
                ):
                    self._remember_polka(self._parse_polka(header["polka"]), block)
            else:
                self._handle_proposal(header, block)
            self._drain_pending()
        elif kind == "SYNC_REQUEST":
            if (not self._authentic(data, sender) or type(data["height"]) is not int
                    or data["height"] < 0 or data["height"] != envelope.height):
                raise ValueError("invalid sync request")
            # Send one missing height per request, preventing catch-up floods
            # from repeatedly blocking an otherwise correct recovering peer.
            height = data["height"] + 1
            if height <= self.committed_height:
                block, cert = self.chain[height], self.certificates[height]
                self._announce(self._make_header("FINALIZE", block, cert.round, certificate=cert), block, [sender])
        else:
            raise ValueError("unknown message kind")

    def _request_sync(self) -> None:
        self.network.broadcast(self.node_id, self._signed({"sender_id": self.node_id,
                               "height": self.committed_height}), kind="SYNC_REQUEST", height=self.committed_height)

    def _schedule_gossip(self) -> None:
        self.scheduler.cancel(self._gossip_handle)
        self._gossip_handle = self.scheduler.schedule_after(self.gossip_interval, self._gossip, tag="node-gossip")

    def _gossip(self) -> None:
        if not self.running or self.crashed:
            return
        self._request_sync()
        for header, block in tuple(self._outgoing.values()):
            if (header["height"], header["round"], header["purpose"]) == (
                self.engine.height, self.engine.round, "PROPOSAL"
            ) and not self.silent_proposer:
                self._announce(header, block)
        for vote in self.engine.vote_pool.get_round_votes(self.engine.height, self.engine.round, Phase.PREVOTE):
            if vote.voter_id == self.node_id:
                self.network.broadcast(self.node_id, vote.to_dict(), kind=vote.phase.value, height=vote.height)
        for vote in self.engine.vote_pool.get_round_votes(self.engine.height, self.engine.round, Phase.PRECOMMIT):
            if vote.voter_id == self.node_id:
                self.network.broadcast(self.node_id, vote.to_dict(), kind=vote.phase.value, height=vote.height)
        latest = max(self._known_polkas.values(), key=lambda p: (p.round, p.block_id), default=None)
        for proof in (latest,) if latest else ():
            block = self.blocks[proof.block_id]
            self._announce(self._make_header("VALID", block, proof.round, polka=proof), block)
        for header_id, header in tuple(self._headers.items()):
            if header_id not in self._received_bodies and header["height"] >= self.engine.height:
                self.network.request_body(self.node_id, header["sender_id"], header_id, height=header["height"])
        self._drain_pending()
        self._schedule_gossip()
