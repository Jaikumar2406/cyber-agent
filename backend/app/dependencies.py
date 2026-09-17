"""Dependency registry - which engines a scan mode requires.

Decouples the Mode Selector from engine availability. Engines register
themselves here as they ship (Agent 1 -> Phase 1, Agent 2 -> Phase 2, Crypto
Engine -> Phase 3). Phase 0: no engine ships yet, but the mapping is complete
so MODE_2/MODE_3 select correctly the day their engines exist.
"""

from dataclasses import dataclass

from app.schemas.common import ScanMode


@dataclass(frozen=True)
class DependencySpec:
    engines: tuple[str, ...]
    capabilities: tuple[str, ...]


_ENGINES = {
    "runtime_security_agent": None,  # Phase 1
    "code_security_agent": None,     # Phase 2
    "crypto_engine": None,           # Phase 3
}

_MODE_DEPENDENCIES: dict[ScanMode, DependencySpec] = {
    ScanMode.MODE_1: DependencySpec(
        engines=("runtime_security_agent",),
        capabilities=("runtime.web_discovery", "runtime.auth_analysis", "runtime.security_tests"),
    ),
    ScanMode.MODE_2: DependencySpec(
        engines=("code_security_agent", "crypto_engine"),
        capabilities=("code.sast", "code.dependencies", "code.secrets", "crypto.discovery"),
    ),
    ScanMode.MODE_3: DependencySpec(
        engines=("runtime_security_agent", "code_security_agent", "crypto_engine"),
        capabilities=(
            "runtime.web_discovery",
            "runtime.security_tests",
            "code.sast",
            "code.dependencies",
            "crypto.discovery",
            "correlation",
        ),
    ),
}


def scan_mode_dependencies(mode: ScanMode) -> DependencySpec:
    return _MODE_DEPENDENCIES[mode]


def available_engines(mode: ScanMode) -> tuple[str, ...]:
    """Engines whose implementation has actually shipped.

    Phase 0 returns an empty tuple for every mode - the harness routes requests
    to the probe tool instead. Each phase replaces this with real registration.
    """
    return ()


def missing_engines(mode: ScanMode) -> tuple[str, ...]:
    spec = scan_mode_dependencies(mode)
    return tuple(e for e in spec.engines if e not in available_engines(mode))