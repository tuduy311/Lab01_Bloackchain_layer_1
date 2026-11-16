# Reproducible scenarios

`T1_normal.json` through `T8_replay.json` are the eight acceptance scenarios
from Lab 01. Run them with `py main.py --config scenarios/<file>.json`; run the
full assertion suite with `py main.py --test`.

T3 injects a signed vote from the wrong chain and a vote with a broken
signature. T4 replays the same signed transaction. T7 configures the
deterministically selected round-0 proposer to equivocate. These injections
are exercised by `tests/test_lab_scenarios.py`.
