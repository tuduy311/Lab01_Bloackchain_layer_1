"""Deterministic multi-validator blockchain simulation.

Run a small demonstration with ``python -m src.blockchain_simulator``. Network
and node logs are merged in callback order; no real time or threads are used.
The application distributes workload transactions to each node explicitly.
Seed-derived keys are exclusively for reproducible laboratory simulations.
"""

from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass, field, replace
from typing import Dict, Iterable, Optional, Tuple

from src.consensus.proposer import ProposerSelector
from src.consensus.timeout import TimeoutConfig
from src.crypto import ValidatorKeyStore, sign_transaction
from src.execution import create_genesis_state
from src.models import Transaction
from src.network import Network, NetworkConfig, NetworkEvent
from src.node import Node
from src.scheduler import Scheduler


@dataclass(frozen=True)
class SimulationConfig:
    num_nodes: int = 8
    seed: int = 0
    network: Optional[NetworkConfig] = None
    timeout: TimeoutConfig = field(default_factory=TimeoutConfig)
    gossip_interval: float = 0.25
    max_transactions: int = 100
    # Keys may be logical validator IDs or external account public keys.
    # None funds every validator with 1000; {} creates an empty world state.
    initial_balances: Optional[Dict[str, int]] = None
    faulty_nodes: Tuple[str, ...] = ()
    silent_proposers: Tuple[str, ...] = ()

    def validate(self) -> None:
        if type(self.num_nodes) is not int or self.num_nodes < 1:
            raise ValueError("num_nodes must be a positive integer")
        if type(self.seed) is not int:
            raise ValueError("seed must be an integer")
        if not math.isfinite(self.gossip_interval) or self.gossip_interval <= 0:
            raise ValueError("gossip_interval must be finite and positive")
        if type(self.max_transactions) is not int or self.max_transactions < 1:
            raise ValueError("max_transactions must be a positive integer")
        self.timeout.validate()
        ids = {f"node_{i + 1}" for i in range(self.num_nodes)}
        if not set(self.faulty_nodes).issubset(ids) or not set(self.silent_proposers).issubset(ids):
            raise ValueError("scenario contains unknown validator IDs")
        if set(self.faulty_nodes) == ids:
            raise ValueError("at least one non-faulty node is required")
        if self.initial_balances is not None:
            if any(type(balance) is not int or balance < 0 for balance in self.initial_balances.values()):
                raise ValueError("genesis balances must be non-negative integers")
        if self.network is not None:
            replace(self.network, num_nodes=self.num_nodes, seed=self.seed).require_valid()


@dataclass(frozen=True)
class SimulationResult:
    completed: bool
    stop_reason: str
    simulation_time: float
    processed_events: int
    finalized_blocks_by_node: Dict[str, tuple]
    state_roots_by_node: Dict[str, str]
    network_counters: Dict[str, int]
    log: tuple

    def to_dict(self) -> dict:
        return asdict(self)


class BlockchainSimulator:
    """Own the shared clock/network and independent validator nodes.

    ``config.seed`` and ``num_nodes`` override those fields of network config.
    Declared faulty nodes are excluded only from the target-height condition;
    they are not automatically crashed. Fault schedules explicitly control them.
    Liveness is expected only within the configured Byzantine fault bound and
    with sufficient delivery/timeout/rate-limit capacity.
    """

    def __init__(self, config: Optional[SimulationConfig] = None, *,
                 transactions: Iterable[Transaction] = (),
                 key_store: Optional[ValidatorKeyStore] = None) -> None:
        self.config = config or SimulationConfig()
        self.config.validate()
        self.scheduler = Scheduler()
        self.node_ids = tuple(f"node_{i + 1}" for i in range(self.config.num_nodes))
        self.key_store = key_store or ValidatorKeyStore(list(self.node_ids), seed=self.config.seed)
        if self.key_store.validator_ids != self.node_ids:
            raise ValueError("key store must match the ordered validator IDs")
        self.public_keys = {node: self.key_store.public_key(node) for node in self.node_ids}
        self.selector = ProposerSelector(self.node_ids, seed=self.config.seed)
        self.log: list[dict] = []
        network_config = replace(self.config.network or NetworkConfig(),
                                 num_nodes=self.config.num_nodes, seed=self.config.seed)
        self.network = Network(self.scheduler, network_config, self.node_ids, self._on_network_event)
        balances = self.config.initial_balances
        if balances is None:
            balances = {node: 1000 for node in self.node_ids}
        resolved = {}
        for address, balance in balances.items():
            address = self.public_keys.get(address, address)
            if address in resolved:
                raise ValueError("multiple genesis entries resolve to the same account")
            resolved[address] = balance
        self.genesis_state = create_genesis_state(resolved)
        self.nodes = {
            node: Node(
                node, self.node_ids, self.scheduler, self.network,
                self.key_store.private_key(node), self.public_keys, self.genesis_state,
                proposer_selector=self.selector, timeout_config=self.config.timeout,
                gossip_interval=self.config.gossip_interval,
                max_transactions=self.config.max_transactions,
                silent_proposer=node in self.config.silent_proposers,
                event_sink=self._on_node_event,
            ) for node in self.node_ids
        }
        self.faulty_nodes = set(self.config.faulty_nodes)
        self._running = False
        for tx in transactions:
            self.submit_transaction(tx)

    @property
    def correct_nodes(self) -> tuple:
        return tuple(node for node in self.node_ids if node not in self.faulty_nodes)

    def _on_network_event(self, event: NetworkEvent) -> None:
        self.log.append({"source": "network", **event.to_dict()})

    def _on_node_event(self, event: dict) -> None:
        self.log.append({"source": "node", **event})

    def make_transaction(self, sender_id: str, receiver_id: str, amount: int, nonce: int) -> Transaction:
        """Sign a workload transaction between two logical validator accounts."""
        if sender_id not in self.nodes or receiver_id not in self.nodes:
            raise ValueError("transaction endpoints must be known validator IDs")
        if type(amount) is not int or amount < 0 or type(nonce) is not int or nonce < 0:
            raise ValueError("amount and nonce must be non-negative integers")
        return sign_transaction(Transaction(self.public_keys[sender_id], self.public_keys[receiver_id],
                                            amount, nonce), self.key_store.private_key(sender_id))

    def submit_transaction(self, tx: Transaction, recipients: Optional[Iterable[str]] = None) -> dict:
        """Explicit workload distribution, not a simulated transaction gossip protocol."""
        targets = self.node_ids if recipients is None else tuple(recipients)
        if not set(targets).issubset(self.nodes):
            raise ValueError("unknown transaction recipient")
        return {node: self.nodes[node].submit_transaction(tx) for node in targets}

    def _check_time(self, time: float) -> None:
        if not math.isfinite(time) or time < self.scheduler.now:
            raise ValueError("scenario time must be finite and not in the past")

    def schedule_transaction(self, time: float, tx: Transaction,
                             recipients: Optional[Iterable[str]] = None) -> None:
        self._check_time(time)
        targets = None if recipients is None else tuple(recipients)
        if targets is not None and not set(targets).issubset(self.nodes):
            raise ValueError("unknown transaction recipient")
        self.scheduler.schedule_at(time, self.submit_transaction, tx, targets, tag="workload")

    def schedule_crash(self, node_id: str, time: float, *, recover_at: Optional[float] = None) -> None:
        self._check_time(time)
        if node_id not in self.nodes:
            raise ValueError("unknown node")
        if recover_at is not None:
            self._check_time(recover_at)
            if recover_at <= time:
                raise ValueError("recovery must follow crash")
        elif len(self.faulty_nodes | {node_id}) == len(self.nodes):
            raise ValueError("at least one non-faulty node is required")
        if recover_at is None:
            self.faulty_nodes.add(node_id)
        self.scheduler.schedule_at(time, self.nodes[node_id].crash, tag="crash")
        if recover_at is not None:
            self.scheduler.schedule_at(recover_at, self.nodes[node_id].recover, tag="recover")

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        for node in self.nodes.values():
            node.start()

    def stop(self) -> None:
        for node in self.nodes.values():
            node.stop()
        self._running = False

    def reached_height(self, height: int) -> bool:
        return all(self.nodes[node].committed_height >= height for node in self.correct_nodes)

    def assert_invariants(self) -> None:
        """Check honest-node safety, chain continuity and committed state roots."""
        agreed = {}
        for node_id in self.correct_nodes:
            node = self.nodes[node_id]
            for height, block in sorted(node.chain.items()):
                if height == 0:
                    continue
                if block.parent_id != node.chain[height - 1].block_id:
                    raise AssertionError(f"broken parent at {node_id}:{height}")
                previous = agreed.setdefault(height, block.block_id)
                if previous != block.block_id:
                    raise AssertionError(f"conflicting finalized blocks at height {height}")
                if not node.engine.verify_certificate(node.certificates[height]):
                    raise AssertionError(f"invalid certificate at {node_id}:{height}")
            if node.committed_height and node.world_state.state_root() != node.chain[node.committed_height].state_root:
                raise AssertionError(f"committed state root mismatch at {node_id}")
            if node.engine.height != node.committed_height + 1:
                raise AssertionError(f"engine/chain height mismatch at {node_id}")

    def run(self, target_height: int = 3, *, max_simulation_time: float = 30.0,
            max_events: int = 100_000) -> SimulationResult:
        """Run until all correct nodes reach the target, or a bound is hit.

        max_simulation_time is an ABSOLUTE simulation-time boundary. Timers
        are stopped on return; a later call may resume with a later boundary.
        processed_events in the result counts callbacks from this call only.
        """
        if type(target_height) is not int or target_height < 0:
            raise ValueError("target_height must be a non-negative integer")
        if type(max_events) is not int or max_events < 1:
            raise ValueError("max_events must be a positive integer")
        self._check_time(max_simulation_time)
        self.start()
        before = self.scheduler.processed_events
        reason = "target_height"
        try:
            while not self.reached_height(target_height):
                if self.scheduler.processed_events - before >= max_events:
                    reason = "max_events"
                    break
                next_time = self.scheduler.peek_time()
                if next_time is None:
                    reason = "idle"
                    break
                if next_time > max_simulation_time:
                    self.scheduler.run_until(max_simulation_time)
                    reason = "max_simulation_time"
                    break
                self.scheduler.step()
            self.assert_invariants()
        finally:
            self.stop()
        return SimulationResult(
            completed=self.reached_height(target_height), stop_reason=reason,
            simulation_time=self.scheduler.now,
            processed_events=self.scheduler.processed_events - before,
            finalized_blocks_by_node={node: tuple(n.chain[h].block_id for h in sorted(n.chain) if h)
                                      for node, n in self.nodes.items()},
            state_roots_by_node={node: n.world_state.state_root() for node, n in self.nodes.items()},
            network_counters=dict(self.network.counters),
            log=tuple(dict(record) for record in self.log),
        )


def main() -> None:
    simulator = BlockchainSimulator()
    simulator.submit_transaction(simulator.make_transaction("node_1", "node_2", 100, 0))
    result = simulator.run(target_height=3)
    summary = result.to_dict()
    summary.pop("log")
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
