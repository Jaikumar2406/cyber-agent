"""AEGIS - application configuration.

All settings come from environment variables (pydantic-settings), prefixed by
nothing (DATABASE_URL, REDIS_URL) or nested under AEGIS_ where custom.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", env_prefix="AEGIS_")

    app_name: str = "AEGIS"
    environment: str = "development"
    debug: bool = True

    # Control plane - single tenant credentials
    api_key: str = "dev-key-change-me"
    default_user: str = "admin"

    # Persistence
    database_url: str = "sqlite+aiosqlite:///./aegis.db"
    redis_url: str = "redis://localhost:6379/0"

    # Scope & policy guard (Phase 1) - empty string means "no constraint"
    allowed_targets: str = ""  # comma separated hosts; "" == deny-by-default
    allowed_domains: str = ""  # comma separated domains (wildcards: *.example.com); overrides allowed_targets when set
    blocked_domains: str = ""  # comma separated domains (wildcards) - hard block, wins over allowed
    allowed_cidrs: str = ""  # comma separated CIDR ranges; empty -> IP-range check disabled
    blocked_cidrs: str = ""  # comma separated CIDR ranges - hard block, wins over allowed
    allowed_path_globs: str = ""  # comma separated path globs; empty -> all paths allowed
    denied_path_globs: str = ""  # comma separated path globs - hard block, wins over allowed
    default_intensity: str = "passive"  # passive | active | aggressive

    # Local ephemeral canary listener for SSRF validation (rules.md §3.5)
    canary_host: str = "127.0.0.1"
    canary_port: int = 0  # 0 = bind an ephemeral port

    # Harness defaults
    sandbox_mode: str = "process"  # "process" | "docker"
    max_tool_timeout_seconds: float = 30.0
    max_tool_calls: int = 100
    max_llm_calls: int = 50
    max_scan_seconds: float = 1800.0
    max_retries: int = 3
    retry_base_backoff_seconds: float = 0.5

    # Attack Surface Discovery (phases.md §1.2) - crawler caps
    discovery_max_pages: int = 20
    discovery_max_depth: int = 3

    # Nuclei engine (phases.md §1.5) - strictly local/offline: the binary is
    # resolved from PATH or an explicit path, and templates come only from the
    # bundled template directory. No template downloads, ever (rules.md §10).
    nuclei_binary: str = "nuclei"  # absolute path or name resolvable on PATH
    nuclei_templates_dir: str = ""  # absolute path to the bundled offline templates

    # Offline local LLM (phases.md §1.9/§5, rules.md §2). The deterministic
    # planner always runs and DECIDES; an offline local model (e.g. a Qwen3-4B
    # Q4_K_M GGUF loaded via llama-cpp-python) only ANNOTATES/explains the
    # plan. The LLM is never on any network path and never invents findings.
    llm_enabled: bool = False  # AEGIS_LLM_ENABLED - master switch
    llm_model_path: str = ""  # AEGIS_LLM_MODEL_PATH - absolute path to a local .gguf
    llm_n_ctx: int = 4096  # AEGIS_LLM_N_CTX - context window
    llm_n_threads: int = 4  # AEGIS_LLM_N_THREADS - CPU threads
    llm_max_tokens: int = 512  # AEGIS_LLM_MAX_TOKENS - max generated tokens
    llm_timeout_seconds: float = 60.0  # AEGIS_LLM_TIMEOUT_SECONDS - hard cap per call

    @property
    def allowed_targets_list(self) -> list[str]:
        parts = [p.strip() for p in self.allowed_targets.split(",") if p.strip()]
        return parts

    @property
    def allowed_domains_list(self) -> list[str]:
        return [p.strip() for p in self.allowed_domains.split(",") if p.strip()]

    @property
    def blocked_domains_list(self) -> list[str]:
        return [p.strip() for p in self.blocked_domains.split(",") if p.strip()]

    @property
    def allowed_cidr_list(self) -> list[str]:
        return [p.strip() for p in self.allowed_cidrs.split(",") if p.strip()]

    @property
    def blocked_cidr_list(self) -> list[str]:
        return [p.strip() for p in self.blocked_cidrs.split(",") if p.strip()]

    @property
    def allowed_path_list(self) -> list[str]:
        return [p.strip() for p in self.allowed_path_globs.split(",") if p.strip()]

    @property
    def denied_path_list(self) -> list[str]:
        return [p.strip() for p in self.denied_path_globs.split(",") if p.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()