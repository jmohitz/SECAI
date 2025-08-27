from __future__ import annotations
import os
from langchain_openai import ChatOpenAI
from .base import BaseLLM
from logger_config import get_logger

logger = get_logger(__name__)

_OPENAI_MODEL_ALIASES = {
    # === GPT-5 family ===
    "gpt-5": "gpt-5",
    "gpt-5-mini": "gpt-5-mini",
    "5": "gpt-5",
    "5-mini": "gpt-5-mini",

    # === GPT-4.5 ===
    "gpt-4.5": "gpt-4.5",
    "4.5": "gpt-4.5",

    # === GPT-4.1 family ===
    "gpt-4.1": "gpt-4.1",
    "gpt-4.1-mini": "gpt-4.1-mini",
    "4.1": "gpt-4.1",
    "4.1-mini": "gpt-4.1-mini",

    # === GPT-4o family ===
    "gpt-4o": "gpt-4o",
    "gpt-4o-mini": "gpt-4o-mini",
    "4o": "gpt-4o",
    "4o-mini": "gpt-4o-mini",
    "chatgpt-4o-latest": "gpt-4o",

    # === Reasoning (o-series) ===
    # o4
    "o4-mini": "o4-mini",
    "o4mini": "o4-mini",

    # o3
    "o3": "o3",
    "o3-pro": "o3-pro",
    "o3pro": "o3-pro",
    "o3-mini": "o3-mini",
    "o3mini": "o3-mini",

    # o1
    "o1": "o1",
    "o1-pro": "o1-pro",
    "o1pro": "o1-pro",
    "o1-mini": "o1-mini",
    "o1mini": "o1-mini",
    "o1-preview": "o1-preview",


    "gpt-4": "gpt-4o",
    "gpt-4-turbo": "gpt-4o",
    "gpt-3.5-turbo": "gpt-4o-mini",
}


def _resolve_openai_model(name: str | None) -> str:
    raw = (name or os.getenv("OPENAI_MODEL") or "gpt-4o").strip()
    resolved = _OPENAI_MODEL_ALIASES.get(raw, raw)
    logger.info(f"[OpenAIHandler] Requested={name!r}, Env={os.getenv('OPENAI_MODEL')}, "
                f"Default='gpt-4o' → Resolved={resolved}")
    return resolved

class OpenAIHandler(BaseLLM):
    def __init__(self, model: str | None = None, **kwargs):
        model = _resolve_openai_model(model)
        logger.info(f"[OpenAIHandler] Using model: {model}")
        super().__init__(ChatOpenAI(model=model, **kwargs))
