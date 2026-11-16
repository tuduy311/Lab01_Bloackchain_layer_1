"""Single command-line entry point for simulation, replay and tests."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional

from src.blockchain_simulator import BlockchainSimulator
from scripts.deterministic_check import check_determinism


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config/default.json",
                        help="scenario JSON file")
    parser.add_argument("--target-height", type=int,
                        help="stop after every validator finalizes this height")
    parser.add_argument("--max-events", type=int,
                        help="maximum simulated events before stopping")
    parser.add_argument("--log", default="logs/run.jsonl",
                        help="JSONL event log output")
    parser.add_argument("--state", default="logs/blockchain.json",
                        help="final ledgers and states output")
    parser.add_argument("--check-determinism", action="store_true",
                        help="run the configured scenario twice and compare")
    parser.add_argument("--test", action="store_true",
                        help="run the full unit and end-to-end test suite")
    args = parser.parse_args(argv)

    if args.test:
        try:
            import pytest
        except ImportError as exc:
            parser.error(f"pytest is required for --test: {exc}")
        return int(pytest.main(["-q", "tests"]))

    if args.check_determinism:
        result = check_determinism(args.config)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0 if all((result["logs_identical"],
                         result["final_state_hash_equal"],
                         result["first_converged"],
                         result["second_converged"])) else 1

    simulator = BlockchainSimulator.from_file(args.config)
    result = simulator.run(args.target_height, args.max_events)
    simulator.write_log(Path(args.log))
    simulator.save_blockchain(Path(args.state))
    print(json.dumps(result.to_dict(), sort_keys=True, indent=2))
    return 0 if result.converged and result.safety_holds else 2


if __name__ == "__main__":
    raise SystemExit(main())
