"""Backward-compatible entry point for deterministic_check.py."""

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.deterministic_check import check_determinism, main

__all__ = ["check_determinism", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
