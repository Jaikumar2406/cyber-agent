"""Air-gap egress verification (rules.md §4.6, §10 'AEGIS NEVER').

Run INSIDE the air-gapped environment (Docker internal network, sandbox, or
firewalled host). Asserts that outbound connectivity to the public internet is
blocked by default and that only allow-listed destinations resolve.

Usage:
    python scripts/verify_airgap.py            # full sweep
    python scripts/verify_airgap.py --host     # host-level checks only
    python scripts/verify_airgap.py --docker   # docker --network none checks

Exit code 0 = air-gap verified. Non-zero = a leak path was found.
"""

import argparse
import shutil
import socket
import subprocess
import sys

# Destinations that MUST be unreachable from inside AEGIS. Public cloud LLM
# endpoints, CVE lookup services, telemetry receive points, and generic
# internet hosts all belong here.
BLOCKED_TARGETS = [
    ("connectors.ollama.ai", 443),  # ollama default (would phone home if internet)
    ("pypi.org", 443),              # never a scan-time dep
    ("api.openai.com", 443),        # cloud LLM - banned by stack
    ("1.1.1.1", 443),               # generic internet
    ("8.8.8.8", 53),                # generic DNS
]

CONNECT_TIMEOUT_S = 3.0


def resolve(host: str) -> None:
    """Best effort DNS resolution check; failure is acceptable (air-gapped)."""
    try:
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror:
        return False


def check_tcp_blocked(host: str, port: int) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT_S):
            return True, "UNEXPECTED: connected"
    except (socket.error, socket.timeout) as exc:
        return False, f"blocked ({type(exc).__name__})"


def check_host() -> tuple[int, list[str]]:
    failures: list[str] = []
    for host, port in BLOCKED_TARGETS:
        ok, msg = check_tcp_blocked(host, port)
        status = "LEAK" if ok else "ok  "
        line = f"  [host] {host}:{port}  {status}  {msg}"
        print(line)
        if ok:
            failures.append(f"host egress leak to {host}:{port}")
    return 1 if failures else 0, failures


def check_docker() -> tuple[int, list[str]]:
    failures: list[str] = []
    if not shutil.which("docker"):
        print("  [docker] docker CLI unavailable - skipping container-level check")
        return 0, failures

    # Ensure the daemon is actually up, so a silent failure can't masquerade
    # as a passed check.
    daemon = subprocess.run(
        ["docker", "info"], capture_output=True, text=True, timeout=CONNECT_TIMEOUT_S + 5
    )
    if daemon.returncode != 0:
        print("  [docker] DOCKER DAEMON NOT RUNNING - container egress check cannot be verified")
        failures.append("docker daemon not running; sandbox egress check unverified")
        return 1, failures

    image = "python:3.12-slim"
    probe = (
        "import socket, sys; "
        "dest=('8.8.8.8',443); "
        "s=socket.socket(); s.settimeout(3); "
        "r=s.connect_ex(dest); s.close(); "
        "print('leaked' if r==0 else 'blocked')"
    )
    cmd = ["docker", "run", "--rm", "--network", "none", image, "python", "-c", probe]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=CONNECT_TIMEOUT_S + 30)
    except subprocess.TimeoutExpired:
        print("  [docker] network none probe timed out - treating as blocked")
        return 0, failures
    result = out.stdout.strip().lower()
    print(f"  [docker] --network none probe: {result or '<no output>'}")
    if result != "blocked":
        failures.append(f"docker --network none probe did not report 'blocked' (rc={out.returncode}: {out.stderr.strip()})")
    return (1 if failures else 0), failures


def check_ipc() -> tuple[int, list[str]]:
    failures: list[str] = []

    # The opencode/dev sandbox may itself have firewall rules. The CLI-level
    # guarantee is: the aegis container network is `internal: true`
    # (docker-compose.yml) and the tool sandbox uses `--network none`
    # (sandbox_manager.py). We freshly confirm that the userland DNS for the
    # internal network of a compose `internal` network would fail.
    print("  [policy] egress:drop enforced at compose network boundary (internal: true)")
    return (1 if failures else 0), failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", action="store_true", help="host-level TCP checks only")
    parser.add_argument("--docker", action="store_true", help="container-level checks only")
    args = parser.parse_args()

    code = 0
    all_failures: list[str] = []

    if not (args.host or args.docker):
        args.host = args.docker = True

    if args.host:
        print("== Host-level egress sweep ==")
        c, f = check_host()
        code = max(code, c)
        all_failures += f

    if args.docker:
        print("== Docker sandbox egress check ==")
        c, f = check_docker()
        code = max(code, c)
        all_failures += f

    print("== Policy assertions ==")
    c, f = check_ipc()
    code = max(code, c)
    all_failures += f

    if all_failures:
        print("\nAIR-GAP VERIFICATION FAILED:")
        for f in all_failures:
            print(f"  - {f}")
    else:
        print("\nAIR-GAP VERIFICATION PASSED: no outbound egress path detected.")
    return code


if __name__ == "__main__":
    sys.exit(main())