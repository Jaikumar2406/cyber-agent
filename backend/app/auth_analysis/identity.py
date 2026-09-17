"""Test identity provisioning (phases.md §1.3).

A scan maintains exactly two test identities when it needs cross-user evidence
(BOLA/BFLA, §1.5/§1.6). Identities are *referenced* by findings; raw session
secrets never leave this store in clear text (rules.md §5.5/§5.6).
"""

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone

MAX_IDENTITIES = 2  # two distinct test users, no more (minimizes blast radius)


@dataclass
class IdentityRecord:
    identity_id: str
    credential_id: str
    kind: str  # "form" | "basic" | "bearer"
    username: str
    # Raw session secret (JWT / session cookie value). Held only in this
    # in-memory store; the redacted summary exposes only a sha256 reference.
    session_secret: str | None = None
    session_cookies: dict[str, str] = field(default_factory=dict)
    associated_with: str | None = None  # target URL this identity was proven on
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def redacted(self) -> dict[str, object]:
        return {
            "identity_id": self.identity_id,
            "credential_id": self.credential_id,
            "kind": self.kind,
            "username": self.username,
            "associated_with": self.associated_with,
            "created_at": self.created_at,
            "session_ref": _ref(self.session_secret),
            "cookie_names": sorted(self.session_cookies.keys()),
        }


def _ref(secret: str | None) -> str | None:
    if not secret:
        return None
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]


class IdentityStore:
    """Per-scan store of up to MAX_IDENTITIES test identities.

    Thread/async-safety is not required: a single scan progresses sequentially
    and the Executor serializes tool calls. State can be checkpointed later via
    the redacted summaries (the raw secrets are deliberately not persisted).
    """

    def __init__(self, associations: dict[str, str] | None = None) -> None:
        # credential_id -> label the operator attached ("alice", "bob", ...)
        self._associations = associations or {}
        self._identities: dict[str, IdentityRecord] = {}
        self._by_credential: dict[str, str] = {}

    def next_identity_id(self) -> str:
        return f"id-{secrets.token_hex(4)}"

    def create(
        self,
        *,
        credential_id: str,
        kind: str,
        username: str,
        session_secret: str | None = None,
        session_cookies: dict[str, str] | None = None,
        associated_with: str | None = None,
    ) -> IdentityRecord:
        if credential_id in self._by_credential:
            raise ValueError(f"credential {credential_id} already provisioned an identity")
        if len(self._identities) >= MAX_IDENTITIES:
            raise ValueError(
                f"identity store full ({MAX_IDENTITIES}); a cross-user phase must "
                "never need more than two test identities"
            )
        identity = IdentityRecord(
            identity_id=self.next_identity_id(),
            credential_id=credential_id,
            kind=kind,
            username=username,
            session_secret=session_secret,
            session_cookies=dict(session_cookies or {}),
            associated_with=associated_with,
        )
        self._identities[identity.identity_id] = identity
        self._by_credential[credential_id] = identity.identity_id
        return identity

    def get(self, identity_id: str) -> IdentityRecord | None:
        return self._identities.get(identity_id)

    def by_credential(self, credential_id: str) -> IdentityRecord | None:
        identity_id = self._by_credential.get(credential_id)
        return self.get(identity_id) if identity_id else None

    def all(self) -> list[IdentityRecord]:
        return list(self._identities.values())

    def count(self) -> int:
        return len(self._identities)

    def redacted_summaries(self) -> list[dict[str, object]]:
        return [identity.redacted() for identity in self.all()]