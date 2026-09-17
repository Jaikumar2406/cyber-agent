"""Control Plane - mode selector (stub).

Deterministic mapping from provided inputs to scan mode (PRD §6):

    URL only            -> MODE_1  (Runtime Security Agent)
    Repository only     -> MODE_2  (Code Security Agent + Crypto Engine)
    URL + repository    -> MODE_3  (all engines)

Phase 0 unlocks MODE_1 for routing purposes; MODE_2/MODE_3 engines arrive in
Phases 2/3. The mapping function itself is fully deterministic and unit-tested.
"""

from dataclasses import dataclass

from app.core.logging import get_logger
from app.dependencies import DependencySpec, scan_mode_dependencies
from app.schemas.common import ScanMode

log = get_logger("aegis.control_plane.mode_selector")


class ModeSelectionError(Exception):
    pass


@dataclass(frozen=True)
class ModeSelection:
    mode: ScanMode
    dependencies: DependencySpec
    warnings: list[str]


def select_mode(*, target_url: str | None, target_repo: str | None) -> ModeSelection:
    has_url = bool(target_url and target_url.strip())
    has_repo = bool(target_repo and target_repo.strip())

    if has_url and has_repo:
        mode, warnings = ScanMode.MODE_3, []
    elif has_url:
        mode, warnings = ScanMode.MODE_1, []
    elif has_repo:
        mode, warnings = ScanMode.MODE_2, []
    else:
        raise ModeSelectionError("no scan inputs provided: supply a URL and/or a repository")

    spec = scan_mode_dependencies(mode)
    log.info("mode_selected", mode=mode.value, url=has_url, repo=has_repo, deps=spec.engines)
    return ModeSelection(mode=mode, dependencies=spec, warnings=warnings)