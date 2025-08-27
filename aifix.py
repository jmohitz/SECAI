import os
from dotenv import load_dotenv
from document_processor import DocumentProcessor
from vector_store_manager import VectorStoreManager
from llm_files import get_handler
from rag_pipeline import RAGPipeline
import re
from typing import Dict, Any, Tuple
from logger_config import get_logger
from ccrun import CCRUN

logger = get_logger(__name__)
load_dotenv()

def _parse_provider_and_model(s: str) -> Tuple[str, str | None]:
    """
    Accepts:
      - "OPENAI"                      -> ("OPENAI", None)
      - "GEMINI"                      -> ("GEMINI", None)
      - "OPENAI:gpt-4o-mini"          -> ("OPENAI", "gpt-4o-mini")
      - "GEMINI:gemini-1.5-pro"       -> ("GEMINI", "gemini-2.5")
      - case-insensitive provider
    """
    if not s:
        raise ValueError("llm_model (provider) must be specified: OPENAI | GEMINI | OLLAMA[:model]")
    parts = s.split(":", 1)
    provider = parts[0].strip().upper()
    model = parts[1].strip() if len(parts) == 2 and parts[1].strip() else None
    return provider, model


def ai_fix(code_input: str, rule: str, message: str, llm_model: str, iterations_cc: int) -> Dict[str, Any]:
    logger.info("Inside analysis function")

    provider, selected_model = _parse_provider_and_model(llm_model)
    logger.info(f"[ai_fix] Provider requested: {provider}, Model arg: {selected_model or 'None'}")
    # Choose the right API key env var by provider (OPENAI / GEMINI / OLLAMA)
    if provider == "OPENAI":
        api_key_env = "OPENAI_API_KEY"
    elif provider == "GEMINI":
        api_key_env = "GOOGLE_API_KEY"
    elif provider == "OLLAMA":
        api_key_env = None  # local, no key by default
    else:
        raise ValueError(f"Unsupported provider: {provider}")

    handler = get_handler(
        provider,
        # API key only when needed
        **({"api_key": os.getenv(api_key_env)} if api_key_env else {}),
        # Model flows into OpenAIHandler/GeminiHandler/OllamaHandler; each resolves env defaults too
        model=selected_model,
        temperature=0.1
    )
    logger.info(f"[ai_fix] Handler initialized for provider={provider}, "
            f"model={getattr(handler.llm, 'model', 'unknown')}")

    doc_processor = DocumentProcessor()
    vs_manager = VectorStoreManager()
    rag_pipeline = RAGPipeline(doc_processor, vs_manager, handler)

    CWE_File_Path = r"data/CWE"
    if not os.path.exists("faiss_index"):
        logger.info("Index does not exist, creating one")
        chunks = doc_processor.load_and_split(CWE_File_Path)
        vs_manager.create_store(chunks)
        vs_manager.save_store()
        logger.info("Index created successfully")
    else:
        logger.info("Index exists, loading vector store")
        vs_manager.load_store()

    try:
        logger.info("Starting the RAG pipeline by sending the code snippet")
        response, links, names, java_code = rag_pipeline.run(code_input, rule, message)

        ccrunner = CCRUN(handler)
        final_code, verified = ccrunner.iterate_until_verified(java_code, max_iterations=iterations_cc)
        secure_snippet = handler.extract_fixed_snippet(code_input, final_code)
        final_explanation = handler.final_explanation(code_input, final_code)

        cwe_links = [
            {"cwe": re.sub(r'.*/definitions/(\d+)\.html', r'CWE-\1', link), "name": name, "link": link}
            for link, name in zip(links, names)
        ]

        logger.info("Response is returned via the API")
        return {
            "Vulnerability_name": response.vulnerability_name,
            "Explanation": final_explanation,
            "CWE_references": cwe_links,
            "CogniCrypt_Verified": verified,
            "Final_Secure_Code_Snippet": secure_snippet
        }

    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        return {"error": f"Analysis failed: {str(e)}"}
