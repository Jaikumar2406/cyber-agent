"""Application Model Builder (phases.md §1.4).

Maps every discovered endpoint into a structured record carrying its observed
method, parameters, auth requirements, and response shape. This is the single
source of truth that 1.5 security test modules read to decide WHERE to inject,
WHERE to test cross-user, and WHAT parameter shapes to send.
"""