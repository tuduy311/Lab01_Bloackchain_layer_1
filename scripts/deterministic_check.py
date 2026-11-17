"""Run the same scenario twice and verify the T8 determinism contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.blockchain_simulator import BlockchainSimulator, SimulationConfig
from src.logger import canonical_log_bytes, state_hashes_are_equal


def run_once(nodes: int, seed: int, height: int) -> tuple[bytes, dict]:
    simulator = BlockchainSimulator(SimulationConfig(num_nodes=nodes, seed=seed))
    simulator.submit_transaction(simulator.make_transaction("node_1", "node_2", 100, 0))
    result = simulator.run(target_height=height)
    payload = canonical_log_bytes(result.log)
    return payload, {
        "completed": result.completed,
        "state_roots_by_node": result.state_roots_by_node,
        "state_hash": hashlib.sha256(
            json.dumps(result.state_roots_by_node, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Check byte-identical deterministic runs.")
    parser.add_argument("--nodes", type=int, default=8)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--height", type=int, default=3)
    args = parser.parse_args()

    first_log, first = run_once(args.nodes, args.seed, args.height)
    second_log, second = run_once(args.nodes, args.seed, args.height)
    report = {
        "logs_byte_identical": first_log == second_log,
        "state_hash_identical": first["state_hash"] == second["state_hash"],
        "all_nodes_agree": state_hashes_are_equal(first["state_roots_by_node"]),
        "completed": first["completed"] and second["completed"],
        "log_sha256": hashlib.sha256(first_log).hexdigest(),
        "state_hash": first["state_hash"],
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if all(report.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
