"""Offline local LLM planning annotation (phases.md §1.9 entry, §5 horizon).

The deterministic planner in ``planner.py`` decides; this module gives an
offline local model (e.g. a Qwen3-4B Q4_K_M GGUF loaded through
llama-cpp-python) the job of ANNOTATING that plan with a short, grounded
rationale. Explicitly non-authoritative:

  * findings/severity/confidence never come from here (rules.md §2);
  * the plan is passed in and the LLM only re-states/prioritizes it;
  * a failure, missing model file, missing package, or timeout yields
    ``None`` and the scan proceeds unchanged (graceful degradation);
  * the model runs as a local in-process process - no network path exists,
    no external API, templating stays on-disk (rules.md §10).

Activation: set ``AEGIS_LLM_ENABLED=1`` and point ``AEGIS_LLM_MODEL_PATH`` at
a local GGUF file (e.g. ``Qwen3-4B-Q4_K_M.gguf``). Until then this module on
import defines a disabled annotator and never loads any model.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger("aegis.planner.llm")


class LlmAnnotator:
    """Thin wrapper over llama-cpp-python for plan annotation.

    The heavy import happens lazily only on the first real inference call so
    that scanning remains fast and unaffected when the model is not installed.
    """

    def __init__(self, settings: Any | None = None) -> None:
        import importlib.util

        self._settings = settings or get_settings()
        self._importable = importlib.util.find_spec("llama_cpp") is not None
        self._llm: Any | None = None

    @property
    def enabled(self) -> bool:
        """True only when everything needed is actually present and usable."""
        if not self._importable or not self._settings.llm_enabled:
            return False
        path = (self._settings.llm_model_path or "").strip()
        if not path or not os.path.isfile(path):
            log.info(
                "llm_annotator.disabled",
                reason="model file not present",
                path=path or "<unset>",
            )
            return False
        return True

    def describe(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "package_installed": self._importable,
            "model_path": self._settings.llm_model_path or "",
            "notes": (
                "Annotate-only: the deterministic planner decides the scan plan. "
                "The LLM never classifies findings or sets severity/confidence."
            ),
        }

    async def annotate_plan(self, plan_text: str, *, target: str, timeout: float | None = None) -> list[str] | None:
        """Return a few short annotation strings for a serialized plan.

        Guards: not enabled -> None; missing package -> None; inference error
        or hard timeout -> [] (annotations are best-effort, scan unaffected).
        """
        if not self.enabled:
            return None
        if not self._importable:
            return None

        cap = timeout if timeout is not None else float(self._settings.llm_timeout_seconds)
        try:
            annotations = await asyncio.wait_for(
                asyncio.to_thread(self._generate, plan_text, target),
                timeout=cap,
            )
            return annotations
        except asyncio.TimeoutError:
            log.warning("llm_annotator.timed_out", timeout_s=cap, target=target)
            return []
        except Exception as exc:  # noqa: BLE001 - any local-model failure degrades gracefully
            log.warning("llm_annotator.failed", error=str(exc)[:200], target=target)
            return []

    # ------------------------------------------------------------------ internals

    def _generate(self, plan_text: str, target: str) -> list[str]:
        try:
            from llama_cpp import Llama  # type: ignore[import-not-found]
        except Exception as exc:  # pragma: no cover - import fallback path
            log.warning("llm_annotator.import_failed", error=str(exc)[:200])
            return []

        s = self._settings
        if self._llm is None:
            self._llm = Llama(
                model_path=s.llm_model_path,
                n_ctx=s.llm_n_ctx,
                n_threads=s.llm_n_threads,
                verbose=False,
            )

        prompt = (
            "You are the plan-annotation component of an air-gapped runtime "
            "security scanner. You NEVER decide what to do and NEVER report "
            "findings. Read the deterministic scan plan below for target "
            f"{target!r} and return at most 4 terse bullet notes (one line "
            "each, no markdown headers) explaining the strategy and any "
            "sequencing/coverage caveats.\n\n"
            "PLAN:\n"
            f"{plan_text}\n\n"
            "NOTES:"
        )
        raw = self._llm(
            prompt,
            max_tokens=s.llm_max_tokens,
            temperature=0.2,
            stop=["\n\n"],
            echo=False,
        )
        text = str(((raw or {}).get("choices") or [{}])[0].get("text") or "").strip()
        parsed = [line.lstrip("-* ").strip() for line in text.splitlines() if line.strip()]
        return parsed[:4]

    def shutdown(self) -> None:
        if self._llm is not None:
            try:
                del self._llm
            finally:
                self._llm = None


_annotator: LlmAnnotator | None = None


def get_llm_annotator() -> LlmAnnotator:
    global _annotator
    if _annotator is None:
        _annotator = LlmAnnotator()
    return _annotator