from __future__ import annotations

import os

from langchain_openai import ChatOpenAI

from .base import BaseLLM

from logger_config import get_logger

logger = get_logger(__name__)

_OPENAI_MODEL_ALIASES = {
    # === GPT-4.1 family ===
    "gpt-4.1": "gpt-4.1",
    "gpt-4.1-mini": "gpt-4.1-mini", 
    "gpt-4.1-nano": "gpt-4.1-nano",
    "4.1": "gpt-4.1",
    "4.1-mini": "gpt-4.1-mini",
    "4.1-nano": "gpt-4.1-nano",

    # === GPT-4o family ===
    "gpt-4o": "gpt-4o",
    "gpt-4o-mini": "gpt-4o-mini", 
    "4o": "gpt-4o",
    "4o-mini": "gpt-4o-mini",
}

def _resolve_openai_model(name: str | None) -> str:
    """Resolve OpenAI model name with proper fallback logic."""
    # Get the requested model or use environment variable or default
    raw = name or os.getenv("OPENAI_MODEL") or "gpt-4o-mini"

    # Apply alias mapping
    resolved = _OPENAI_MODEL_ALIASES.get(raw, raw)

    logger.info(
        f"[OpenAIHandler] Requested={name!r}, Env={os.getenv('OPENAI_MODEL')}, "
        f"Default='gpt-4o-mini' -> Resolved={resolved}"
    )

    return resolved

class OpenAIHandler(BaseLLM):
    def __init__(self, model: str | None = None, **kwargs):
        resolved_model = _resolve_openai_model(model)
        logger.info(f"[OpenAIHandler] Using model: {resolved_model}")
        super().__init__(ChatOpenAI(model=resolved_model, **kwargs))
