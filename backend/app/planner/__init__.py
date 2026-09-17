"""Phase 1.9 - Deep Agent Supervisor (runtime slice).

Deterministic planner + re-planner build the Mode-1 tool sequence
(discovery -> auth -> model -> security tests -> evidence), an offline local
LLM annotates (never decides) the plan, and the supervisor executes it through
the Tool Executor - the single enforcement path.
"""