"""Network Policy - egress/allowed-destination control at the Harness level.

The runtime enforcement boundary is the Docker `internal` network + sandbox
`--network none` (see docker-compose.yml and sandbox_manager.py). This module
is the in-code counterpart: the explicit allow-list of destinations a tool may
contact. Phase 1 (Runtime Agent) will consult it before every request.
"""

from dataclasses import dataclass, field

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger("aegis.harness.network_policy")


@dataclass(frozen=True)
class NetworkDecision:
    allowed: bool
    reason: str


class NetworkPolicy:
    """Deny-by-default. Only explicitly authorized local/intranet targets are
    reachable; everything else (including any public internet host) is blocked."""

    def __init__(self, allowed_targets: list[str] | None = None) -> None:
        self.allowed_targets: set[str] = set(
            allowed_targets if allowed_targets is not None else get_settings().allowed_targets_list
        )
        # SSRF canary listener (Phase 1) will be an additional allow-listed sandbox
        # target: host.docker.internal / localhost on the isolated container network.
        self.allowed_targets.add("host.docker.internal")
        self.allowed_targets.add("localhost")
        self.allowed_targets.add("127.0.0.1")

    def check(self, host: str) -> NetworkDecision:
        if host in self.allowed_targets:
            return NetworkDecision(True, f"host {host!r} is allow-listed")
        return NetworkDecision(False, f"host {host!r} is blocked by network policy")

    def assert_reachable(self, host: str) -> None:
        decision = self.check(host)
        log.info("network_policy_check", host=host, allowed=decision.allowed)
        if not decision.allowed:
            raise PermissionError(decision.reason)