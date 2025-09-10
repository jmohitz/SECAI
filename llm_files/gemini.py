from __future__ import annotations
import os
from langchain_google_genai import ChatGoogleGenerativeAI
from .base import BaseLLM
from logger_config import get_logger

logger = get_logger(__name__)

_GEMINI_MODEL_ALIASES = {
    # === Gemini 2.5 family ===
    "gemini-2.5-pro": "gemini-2.5-pro",
    "gemini-2.5-flash": "gemini-2.5-flash",
    "gemini-2.5-flash-lite": "gemini-2.5-flash-lite",
    "2.5-pro": "gemini-2.5-pro",
    "2.5-flash": "gemini-2.5-flash",
    "2.5-flash-lite": "gemini-2.5-flash-lite",
    "2.5lite": "gemini-2.5-flash-lite",

    # === Gemini 2.0 family ===
    "gemini-2.0-pro": "gemini-2.0-pro",
    "gemini-2.0-flash": "gemini-2.0-flash",
    "2.0-pro": "gemini-2.0-pro",
    "2.0-flash": "gemini-2.0-flash",

    # === Gemini 1.5 family ===
    "gemini-1.5-pro": "gemini-1.5-pro",
    "gemini-1.5-flash": "gemini-1.5-flash",
    "gemini-1.5-flash-8b": "gemini-1.5-flash-8b",
    "1.5-pro": "gemini-1.5-pro",
    "1.5-flash": "gemini-1.5-flash",
    "1.5-flash-8b": "gemini-1.5-flash-8b",
    "1.5-8b": "gemini-1.5-flash-8b",    
    "pro": "gemini-2.5-pro",         
    "flash": "gemini-2.5-flash",     
    "flash-lite": "gemini-2.5-flash-lite",
}


def _resolve_gemini_model(name: str | None) -> str:
    raw = (name or os.getenv("GEMINI_MODEL") or "gemini-2.0-flash").strip()
    resolved = _GEMINI_MODEL_ALIASES.get(raw, raw)
    logger.info(f"[GeminiHandler] Requested={name!r}, Env={os.getenv('GEMINI_MODEL')}, "
               f"Default='gemini-2.0-flash' -> Resolved={resolved}")  # Changed → to ->
    return resolved



class GeminiHandler(BaseLLM):
    def __init__(self, model: str | None = None, **kwargs):
        model = _resolve_gemini_model(model)
        logger.info(f"[GeminiHandler] Using model: {model}")
        super().__init__(ChatGoogleGenerativeAI(model=model, **kwargs))
