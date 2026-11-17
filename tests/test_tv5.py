import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.blockchain_simulator import BlockchainSimulator, SimulationConfig
from src.logger import canonical_log_bytes, state_hashes_are_equal


def run_scenario():
    simulator = BlockchainSimulator(SimulationConfig(num_nodes=8, seed=0))
    simulator.submit_transaction(simulator.make_transaction("node_1", "node_2", 100, 0))
    return simulator.run(3)


def test_canonical_log_is_byte_identical_for_same_seed():
    first = run_scenario()
    second = run_scenario()
    assert first.completed and second.completed
    assert canonical_log_bytes(first.log) == canonical_log_bytes(second.log)
    assert first.state_roots_by_node == second.state_roots_by_node
    assert state_hashes_are_equal(first.state_roots_by_node)


def test_canonical_logger_uses_sorted_json_and_jsonl():
    payload = canonical_log_bytes(({"z": 1, "a": 2},))
    assert payload == b'{"a":2,"z":1}\n'
