"""Run a scenario twice and compare logs and final state."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Optional

# Support both ``py -m scripts.deterministic_check`` and direct execution of
# this file from the project root (where sys.path[0] is the scripts folder).
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.blockchain_simulator import BlockchainSimulator


def check_determinism(config_path: str | Path) -> dict:
    """Compare byte-identical logs and final state hashes for two replays."""
    with Path(config_path).open("r", encoding="utf-8") as stream:
        config = json.load(stream)
    first = BlockchainSimulator(config)
    first_result = first.run()
    first_log = first.event_log.jsonl()

    second = BlockchainSimulator(config)
    second_result = second.run()
    second_log = second.event_log.jsonl()

    return {
        "logs_identical": first_log == second_log,
        "final_state_hash_equal": (
            first_result.final_state_hash is not None
            and first_result.final_state_hash == second_result.final_state_hash
        ),
        "first_converged": first_result.converged,
        "second_converged": second_result.converged,
        "final_state_hash": first_result.final_state_hash,
        "log_bytes": len(first_log),
    }


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config/default.json")
    args = parser.parse_args(argv)
    result = check_determinism(args.config)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if all((result["logs_identical"],
                     result["final_state_hash_equal"],
                     result["first_converged"],
                     result["second_converged"])) else 1


if __name__ == "__main__":
    raise SystemExit(main())
