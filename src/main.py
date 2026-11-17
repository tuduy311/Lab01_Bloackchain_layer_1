"""Single command-line entry point for the lab simulator.

Run it as a module from the project root so ``src`` is importable::

    python -m src.main
    python -m src.main --config config/scenario_unstable_network.json
    python -m src.main --nodes 8 --seed 0 --height 3

Defaults come from ``config/simulation.json``; any CLI flag overrides the
matching field of that file.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional

from src.blockchain_simulator import BlockchainSimulator
from src.config import DEFAULT_CONFIG_PATH, RunConfig, load_run_config
from src.logger import canonical_log_bytes, state_hashes_are_equal, write_log


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m src.main",
        description="Run the Lab 01 blockchain simulator.",
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH,
                        help="JSON/YAML run configuration (default: config/simulation.json)")
    parser.add_argument("--nodes", type=int, help="override run.nodes")
    parser.add_argument("--seed", type=int, help="override run.seed")
    parser.add_argument("--height", type=int, help="override run.height")
    parser.add_argument("--log", type=Path, help="override run.log")
    parser.add_argument("--summary", type=Path, help="override run.summary")
    return parser


def resolve_config(args: argparse.Namespace) -> RunConfig:
    """Load the configuration file, then apply CLI overrides."""
    return load_run_config(args.config).with_overrides(
        nodes=args.nodes, seed=args.seed, height=args.height, log=args.log, summary=args.summary,
    )


def run(config: RunConfig) -> dict:
    simulation_config = config.simulator_config()

    def execute():
        simulator = BlockchainSimulator(simulation_config)
        simulator.submit_transaction(simulator.make_transaction("node_1", "node_2", 100, 0))
        return simulator.run(target_height=config.height)

    result = execute()
    log_sha256 = write_log(config.log, result.log)
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
    config.summary.parent.mkdir(parents=True, exist_ok=True)
    config.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main(argv: Optional[list] = None) -> None:
    args = build_parser().parse_args(argv)
    print(json.dumps(run(resolve_config(args)), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
