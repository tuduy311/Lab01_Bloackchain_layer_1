"""Single command-line entry point for the lab simulator."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.blockchain_simulator import BlockchainSimulator, SimulationConfig
from src.logger import canonical_log_bytes, state_hashes_are_equal, write_log


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the Lab 01 blockchain simulator.")
    parser.add_argument("--nodes", type=int, default=8)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--height", type=int, default=3)
    parser.add_argument("--log", type=Path, default=Path("logs/run.jsonl"))
    parser.add_argument("--summary", type=Path, default=Path("logs/summary.json"))
    return parser


def run(args: argparse.Namespace) -> dict:
    def execute():
        simulator = BlockchainSimulator(SimulationConfig(num_nodes=args.nodes, seed=args.seed))
        simulator.submit_transaction(simulator.make_transaction("node_1", "node_2", 100, 0))
        return simulator.run(target_height=args.height)

    result = execute()
    log_sha256 = write_log(args.log, result.log)
    replay = execute()
    deterministic = {
        "logs_byte_identical": canonical_log_bytes(result.log) == canonical_log_bytes(replay.log),
        "state_hash_identical": result.state_roots_by_node == replay.state_roots_by_node,
        "all_nodes_agree": state_hashes_are_equal(result.state_roots_by_node),
    }
    summary = result.to_dict()
    summary.pop("log", None)
    summary["log_sha256"] = log_sha256
    summary["deterministic_check"] = deterministic
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    args = build_parser().parse_args()
    print(json.dumps(run(args), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
