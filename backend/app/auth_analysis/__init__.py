"""Authentication Analysis - Phase 1.3 (phases.md §1.3).

Detects how a target authenticates (JWT, cookie/session, OAuth, Basic, api-key)
and provisions two distinct test identities for cross-user testing (BOLA/BFLA,
rules.md §3.4: test identities must be explicitly supplied by the authorized
user - no brute-forcing, no credential theft).

Supports §1.4 (which endpoints are authenticated), §1.5 (cross-identity tests),
and §1.6 (auth-identity proof on every cross-user finding).
"""