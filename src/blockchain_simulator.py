"""End-to-end deterministic Layer-1 simulator and configuration loader."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

from src.consensus.proposer import ProposerSelector
from src.consensus.timeout import TimeoutConfig
from src.crypto import public_key_from_private, sign_transaction
from src.logger import EventLog
from src.execution import WorldState, create_genesis_state
from src.models import Block, Transaction, genesis_block
from src.network.network import MIN_NODES, Network, NetworkConfig
from src.node import Node
from src.scheduler import Scheduler


@dataclass(frozen=True)
class SimulationResult:
    """Read-only summary of one simulator run."""

    target_height: int
    events_processed: int
    converged: bool
    safety_holds: bool
    final_state_hash: Optional[str]
    node_heads: Dict[str, str]
    node_state_roots: Dict[str, str]
    ledgers: Dict[str, Tuple[str, ...]]

    def to_dict(self) -> dict:
        return {
            "target_height": self.target_height,
            "events_processed": self.events_processed,
            "converged": self.converged,
            "safety_holds": self.safety_holds,
            "final_state_hash": self.final_state_hash,
            "node_heads": dict(self.node_heads),
            "node_state_roots": dict(self.node_state_roots),
            "ledgers": {node: list(chain) for node, chain in self.ledgers.items()},
        }


class BlockchainSimulator:
    """Compose independent validator nodes over the event-driven network."""

    def __init__(self, config: Optional[dict] = None) -> None:
        raw = dict(config or {})
        self.chain_id = str(raw.get("chain_id", "lab01"))
        self.seed = int(raw.get("seed", 1))
        self.num_nodes = int(raw.get("num_nodes", MIN_NODES))
        if self.num_nodes < MIN_NODES:
            raise ValueError(f"a lab simulation needs at least {MIN_NODES} validators")
        self.validators = tuple(f"node_{i + 1}" for i in range(self.num_nodes))
        self.target_height = int(raw.get("target_height", 1))
        self.max_events = int(raw.get("max_events", 100_000))
        self.prestart_gossip = bool(raw.get("prestart_gossip", True))
        if self.target_height < 1 or self.max_events < 1:
            raise ValueError("target_height and max_events must be positive")

        network_data = dict(raw.get("network", {}))
        network_data.setdefault("num_nodes", self.num_nodes)
        network_data.setdefault("seed", self.seed)
        self.network_config = NetworkConfig.from_dict(network_data).require_valid(strict=True)
        if self.network_config.num_nodes != self.num_nodes:
            raise ValueError("network.num_nodes must match num_nodes")
        timeout_data = dict(raw.get("timeout", {}))
        self.timeout_config = TimeoutConfig(**{
            key: timeout_data[key]
            for key in ("base", "multiplier", "max_timeout", "jitter", "seed", "max_round")
            if key in timeout_data
        })
        self.timeout_config.validate()
        self.silent_slots = {
            (int(item[0]), int(item[1]))
            for item in raw.get("silent_slots", [])
        }
        self.equivocate_slots = {
            (int(item[0]), int(item[1]))
            for item in raw.get("equivocate_slots", [])
        }
        self.equivocating_nodes = set(map(str, raw.get("equivocating_nodes", [])))

        # Fixed keys below are public lab fixtures.  They are unrelated to the
        # simulator seed and must never be used as production credentials.
        configured_keys = raw.get("validator_private_keys")
        if configured_keys is None:
            self.validator_private_keys = {
                node: f"{index + 1:064x}"
                for index, node in enumerate(self.validators)
            }
        else:
            self.validator_private_keys = {
                node: str(configured_keys[node]) for node in self.validators
            }
        self.validator_public_keys = {
            node: public_key_from_private(private)
            for node, private in self.validator_private_keys.items()
        }

        participant_private = raw.get("participant_private_keys", {})
        self.participant_private_keys = {
            str(name): str(private)
            for name, private in participant_private.items()
        }
        if not self.participant_private_keys:
            # Fixed demo identities, not derived from the network/random seed.
            self.participant_private_keys = {
                "alice": hashlib.sha256(b"lab01-public-demo-alice").hexdigest(),
                "bob": hashlib.sha256(b"lab01-public-demo-bob").hexdigest(),
            }
        self.participant_public_keys = {
            name: public_key_from_private(private)
            for name, private in self.participant_private_keys.items()
        }

        balance_config = raw.get("initial_balances")
        if balance_config is None:
            balance_config = {"alice": 1_000, "bob": 0}
        balances: Dict[str, int] = {}
        for participant, amount in balance_config.items():
            address = self.participant_public_keys.get(str(participant), str(participant))
            balances[address] = int(amount)
        self.initial_state = create_genesis_state(balances)

        self.scheduler = Scheduler()
        self.event_log = EventLog()
        self.network = Network(
            self.scheduler,
            self.network_config,
            self.validators,
            event_sink=self.event_log.append_network_event,
        )
        self.genesis = genesis_block(self.chain_id, self.initial_state.state_root())
        self.selector = ProposerSelector(self.validators, seed=self.seed)
        if raw.get("equivocate_proposer_round0", False):
            self.equivocating_nodes.add(self.selector.proposer_for(1, 0))
            self.equivocate_slots.add((1, 0))
        fault_bound = (self.num_nodes - 1) // 3
        if not self.equivocating_nodes.issubset(set(self.validators)):
            raise ValueError("equivocating_nodes must be validators")
        if len(self.equivocating_nodes) > fault_bound:
            raise ValueError(f"equivocator count exceeds f={fault_bound}")
        self.nodes: Dict[str, Node] = {
            node_id: Node(
                node_id,
                self.validators,
                self.network,
                self.scheduler,
                self.event_log,
                self.initial_state,
                self.genesis,
                self.validator_private_keys[node_id],
                self.validator_public_keys,
                chain_id=self.chain_id,
                proposer_seed=self.seed,
                timeout_config=self.timeout_config,
                silent_slots=self.silent_slots,
                equivocate_slots=(self.equivocate_slots
                                  if node_id in self.equivocating_nodes else ()),
            )
            for node_id in self.validators
        }
        self._started = False
        self._prepared = False
        self._events_processed = 0
        self.demo_transaction: Optional[Transaction] = None

        if raw.get("demo_transfer", True):
            self.demo_transaction = self.add_transfer(
                "alice", "bob", int(raw.get("demo_amount", 25)), 0
            )

    @classmethod
    def from_file(cls, path: str | Path) -> "BlockchainSimulator":
        source = Path(path)
        with source.open("r", encoding="utf-8") as stream:
            data = json.load(stream)
        if not isinstance(data, dict):
            raise ValueError("simulation configuration must be a JSON object")
        return cls(data)

    def add_transfer(self, sender: str, receiver: str, amount: int,
                     nonce: int) -> Transaction:
        if sender not in self.participant_private_keys:
            raise KeyError(f"unknown transaction sender: {sender}")
        if receiver not in self.participant_public_keys:
            raise KeyError(f"unknown transaction receiver: {receiver}")
        template = Transaction(
            self.participant_public_keys[sender],
            self.participant_public_keys[receiver],
            int(amount),
            int(nonce),
            chain_id=self.chain_id,
        )
        tx = sign_transaction(template, self.participant_private_keys[sender])
        self.nodes[self.validators[0]].submit_transaction(tx)
        return tx

    def run(self, target_height: Optional[int] = None,
            max_events: Optional[int] = None) -> SimulationResult:
        """Run until every node finalizes ``target_height`` or the event cap."""
        target = self.target_height if target_height is None else int(target_height)
        event_cap = self.max_events if max_events is None else int(max_events)
        if target < 1 or event_cap < 1:
            raise ValueError("target_height and max_events must be positive")

        if not self._prepared:
            # Normal runs can start from a fully propagated initial mempool.
            # Fault scenarios may leave this disabled to exercise transaction
            # and consensus traffic during the pre-synchrony period.
            if self.prestart_gossip:
                self._events_processed += self.scheduler.run(max_events=event_cap)
            self._prepared = True
        if not self._started:
            for node in self.nodes.values():
                node.start()
            self._started = True

        processed = 0
        while processed < event_cap and not self._all_finalized(target):
            if not self.scheduler.step():
                break
            processed += 1
        self._events_processed += processed
        return self.result(target, self._events_processed)

    def inject_vote(self, vote: Any, recipients: Optional[Iterable[str]] = None) -> None:
        """Queue a vote exactly as a peer would, for fault scenarios and tests."""
        payload = {"vote": vote.to_dict(), "prevote_proof": []}
        self.network.broadcast(
            vote.voter_id,
            payload,
            kind=vote.phase.value,
            height=vote.height,
            recipients=None if recipients is None else tuple(recipients),
        )

    def _all_finalized(self, target_height: int) -> bool:
        return all(node.head.height >= target_height for node in self.nodes.values())

    def result(self, target_height: Optional[int] = None,
               events_processed: Optional[int] = None) -> SimulationResult:
        target = self.target_height if target_height is None else target_height
        heads = {node_id: node.head.block_id for node_id, node in self.nodes.items()}
        roots = {
            node_id: node.state_roots.get(target, node.state_root)
            for node_id, node in self.nodes.items()
        }
        ledgers = {
            node_id: tuple(block.block_id for block in node.ledger
                           if block.height <= target)
            for node_id, node in self.nodes.items()
        }
        all_chains_equal = len(set(ledgers.values())) == 1
        all_roots_equal = len(set(roots.values())) == 1
        reached = all(target in node.state_roots for node in self.nodes.values())
        return SimulationResult(
            target_height=target,
            events_processed=(self._events_processed if events_processed is None
                              else events_processed),
            converged=reached and all_chains_equal and all_roots_equal,
            safety_holds=not any(record.get("event") == "SAFETY_VIOLATION"
                                 for record in self.event_log.records),
            final_state_hash=next(iter(set(roots.values()))) if all_roots_equal else None,
            node_heads=heads,
            node_state_roots=roots,
            ledgers=ledgers,
        )

    def write_log(self, path: str | Path) -> None:
        self.event_log.write(path)

    def save_blockchain(self, path: str | Path) -> None:
        """Write every validator's ledger and state root as deterministic JSON."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            node_id: {
                "blocks": [block.to_dict() for block in node.ledger],
                "state": node.state.to_dict(),
                "state_root": node.state_root,
            }
            for node_id, node in self.nodes.items()
        }
        target.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n",
                          encoding="utf-8")

