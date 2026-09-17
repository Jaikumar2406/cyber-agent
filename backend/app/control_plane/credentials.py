"""Controlled test-credential catalog (rules.md §3.4, "test identities must be
explicitly supplied by the authorized user"; PRD §1.3/§1.6).

Unlike the payload catalog, there is deliberately NO pre-bundled credential.
Every test identity is an explicit, operator-supplied credential that the
authorized user provides per scan (offline config / scan request). The catalog
is the single controlled place those values live; it is referenced by id from
tool calls, never supplied inline - so brute-forcing or ad-hoc credential
injection is structurally impossible.
"""

from dataclasses import dataclass


class CredentialNotAllowed(Exception):
    pass


@dataclass(frozen=True)
class Credential:
    id: str
    kind: str  # "form" | "basic" | "bearer" - how the credential is submitted
    username: str
    secret: str  # password or bearer token; never logged redacted by tools
    description: str


def _to_credential(raw: dict) -> Credential:
    for key in ("id", "kind", "username", "secret", "description"):
        if key not in raw:
            raise ValueError(f"credential entry missing required key {key!r}")
    if raw["kind"] not in ("form", "basic", "bearer"):
        raise ValueError(f"credential {raw['id']!r}: kind must be form|basic|bearer")
    return Credential(
        id=str(raw["id"]),
        kind=str(raw["kind"]),
        username=str(raw["username"]),
        secret=str(raw["secret"]),
        description=str(raw["description"]),
    )


class CredentialCatalog:
    def __init__(self, credentials: dict[str, dict] | list[dict] | None = None) -> None:
        self._by_id: dict[str, Credential] = {}
        entries: list[dict] = []
        if isinstance(credentials, dict):
            for cid, raw in credentials.items():
                entries.append({**raw, "id": cid})
        elif credentials is not None:
            entries = list(credentials)
        for raw in entries:
            credential = _to_credential(raw)
            if credential.id in self._by_id:
                raise ValueError(f"duplicate credential id {credential.id!r}")
            self._by_id[credential.id] = credential

    def by_id(self, credential_id: str | None) -> Credential | None:
        if not credential_id:
            return None
        return self._by_id.get(credential_id)

    def require(self, credential_id: str | None) -> Credential:
        credential = self.by_id(credential_id)
        if credential is None:
            raise CredentialNotAllowed(
                f"credential {credential_id!r} is not in the operator-supplied catalog"
            )
        return credential

    def describe(self) -> list[dict[str, str]]:
        """Redacted listing: never exposes the secret value."""
        return [
            {"id": c.id, "kind": c.kind, "username": c.username, "description": c.description}
            for c in sorted(self._by_id.values(), key=lambda c: c.id)
        ]

    def __len__(self) -> int:
        return len(self._by_id)


_empty_catalog: CredentialCatalog | None = None


def get_empty_credential_catalog() -> CredentialCatalog:
    """Empty default: no implicit credentials exist for any scan."""
    global _empty_catalog
    if _empty_catalog is None:
        _empty_catalog = CredentialCatalog()
    return _empty_catalog