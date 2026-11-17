"""Run configuration loaded from the ``config/`` directory.

A run is fully described by :class:`RunConfig`: how many validators, which
seed, which target height, where the log/summary go, and the network/timeout
parameters of the scenario.  Those values live in ``config/simulation.json``
(JSON or YAML) instead of being hard-coded in the entry point, so the same
scenario can be replayed without editing code.

Relative paths inside a configuration file are resolved against the project
root, not against the current working directory, so ``python -m src.main``
behaves the same from any directory.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Union

import yaml

from src.blockchain_simulator import SimulationConfig
from src.consensus.timeout import TimeoutConfig
from src.network import NetworkConfig

PROJECT_ROOT = Path(__file__).resolve().parents[1]
"""Repository root; the directory that holds ``src/``, ``config/`` and ``tests/``."""

DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "simulation.json"
"""Configuration used when the CLI does not pass ``--config``."""

DEFAULT_LOG_PATH = PROJECT_ROOT / "logs" / "run.jsonl"
DEFAULT_SUMMARY_PATH = PROJECT_ROOT / "logs" / "summary.json"


@dataclass(frozen=True)
class RunConfig:
    """Everything the entry point needs for one deterministic run.

    Attributes
    ----------
    nodes, seed : int
        Validator count and master seed handed to :class:`SimulationConfig`.
    height : int
        Number of finalized blocks the run waits for.
    log, summary : Path
        JSONL event log and JSON summary written by the entry point.
    simulation : SimulationConfig
        Network, timeout and simulation parameters of the scenario.
    """

    nodes: int = 8
    seed: int = 0
    height: int = 3
    log: Path = DEFAULT_LOG_PATH
    summary: Path = DEFAULT_SUMMARY_PATH
    simulation: SimulationConfig = field(default_factory=SimulationConfig)

    def simulator_config(self) -> SimulationConfig:
        """Validated :class:`SimulationConfig` aligned with ``nodes``/``seed``."""
        config = replace(self.simulation, num_nodes=self.nodes, seed=self.seed)
        config.validate()
        return config

    def with_overrides(self, **overrides: Any) -> "RunConfig":
        """Return a copy with the non-``None`` overrides applied."""
        applied = {key: value for key, value in overrides.items() if value is not None}
        return replace(self, **applied)


def _read_mapping(path: Path) -> Dict[str, Any]:
    """Parse a JSON or YAML configuration file and return its root mapping."""
    if not path.is_file():
        raise FileNotFoundError(f"configuration file not found: {path}")
    text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(text) if path.suffix.lower() in {".yaml", ".yml"} else json.loads(text)
    if data is None:
        return {}
    if not isinstance(data, Mapping):
        raise ValueError(f"configuration root must be a mapping: {path}")
    return dict(data)


def _section(data: Mapping[str, Any], name: str) -> Dict[str, Any]:
    """Return an optional mapping section of the configuration file."""
    value = data.get(name) or {}
    if not isinstance(value, Mapping):
        raise ValueError(f"configuration section '{name}' must be a mapping")
    return dict(value)


def _known_fields(cls: type) -> set:
    return {item.name for item in fields(cls)}


def _resolve_path(value: Optional[Union[str, Path]], default: Path) -> Path:
    """Resolve a configured path; relative paths are anchored at the project root."""
    if value is None:
        return default
    path = Path(value)
    return path if path.is_absolute() else PROJECT_ROOT / path


def load_run_config(path: Optional[Union[str, Path]] = None) -> RunConfig:
    """Build a :class:`RunConfig` from a JSON/YAML file.

    Parameters
    ----------
    path : str or Path, optional
        Configuration file; defaults to ``config/simulation.json``.

    Raises
    ------
    FileNotFoundError
        If the file does not exist.
    ValueError
        If the file is malformed or the resulting configuration is invalid.
    """
    target = DEFAULT_CONFIG_PATH if path is None else Path(path)
    data = _read_mapping(target)
    defaults = RunConfig()
    run = _section(data, "run")
    simulation = _section(data, "simulation")

    network_defaults = defaults.simulation.network or NetworkConfig()
    network = NetworkConfig.from_dict(_section(data, "network")) if "network" in data else network_defaults
    timeout = (
        TimeoutConfig(**{k: v for k, v in _section(data, "timeout").items() if k in _known_fields(TimeoutConfig)})
        if "timeout" in data else defaults.simulation.timeout
    )
    simulation_defaults = defaults.simulation

    config = RunConfig(
        nodes=run.get("nodes", defaults.nodes),
        seed=run.get("seed", defaults.seed),
        height=run.get("height", defaults.height),
        log=_resolve_path(run.get("log"), defaults.log),
        summary=_resolve_path(run.get("summary"), defaults.summary),
        simulation=SimulationConfig(
            num_nodes=run.get("nodes", defaults.nodes),
            seed=run.get("seed", defaults.seed),
            network=network,
            timeout=timeout,
            gossip_interval=simulation.get("gossip_interval", simulation_defaults.gossip_interval),
            max_transactions=simulation.get("max_transactions", simulation_defaults.max_transactions),
            initial_balances=simulation.get("initial_balances", simulation_defaults.initial_balances),
            faulty_nodes=tuple(simulation.get("faulty_nodes", simulation_defaults.faulty_nodes)),
            silent_proposers=tuple(simulation.get("silent_proposers", simulation_defaults.silent_proposers)),
        ),
    )
    if type(config.height) is not int or config.height < 0:
        raise ValueError("height must be a non-negative integer")
    config.simulator_config()
    return config
