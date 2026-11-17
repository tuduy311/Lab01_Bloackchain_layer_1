"""Run the same scenario twice and verify the T8 determinism contract.

Usage, from the project root::

    python -m src.deterministic_check
    python -m src.deterministic_check --config config/scenario_unstable_network.json
    python -m src.deterministic_check --nodes 8 --seed 0 --height 3

Defaults come from ``config/simulation.json``; CLI flags override it. The exit
status is ``0`` only when both runs are byte-identical, agree on the state
hash, complete, and every node reports the same state root.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Optional

if __package__ in (None, ""):  # allow "python src/deterministic_check.py" as well
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.blockchain_simulator import BlockchainSimulator
from src.config import DEFAULT_CONFIG_PATH, RunConfig, load_run_config
from src.logger import canonical_log_bytes, state_hashes_are_equal


def run_once(config: RunConfig) -> tuple[bytes, dict]:
    simulator = BlockchainSimulator(config.simulator_config())
    simulator.submit_transaction(simulator.make_transaction("node_1", "node_2", 100, 0))
    result = simulator.run(target_height=config.height)
    payload = canonical_log_bytes(result.log)
    return payload, {
        "completed": result.completed,
        "state_roots_by_node": result.state_roots_by_node,
        "state_hash": hashlib.sha256(
            json.dumps(result.state_roots_by_node, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check byte-identical deterministic runs.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH,
                        help="JSON/YAML run configuration (default: config/simulation.json)")
    parser.add_argument("--nodes", type=int, help="override run.nodes")
    parser.add_argument("--seed", type=int, help="override run.seed")
    parser.add_argument("--height", type=int, help="override run.height")
    return parser


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)
    config = load_run_config(args.config).with_overrides(
        nodes=args.nodes, seed=args.seed, height=args.height,
    )

    first_log, first = run_once(config)
    second_log, second = run_once(config)
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
