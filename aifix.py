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

# Initialize logging and load environment variables (API keys, etc.)
logger = get_logger(__name__)
load_dotenv()


def _parse_provider_and_model(s: str) -> Tuple[str, str | None]:
    """
    Parses the LLM provider string to extract provider name and optional model.
    This allows flexible model specification from the frontend.
    
    Examples of accepted formats:
      - "OPENAI"                      -> ("OPENAI", None) - uses default model
      - "GEMINI"                      -> ("GEMINI", None) - uses default model  
      - "OPENAI:gpt-4o-mini"          -> ("OPENAI", "gpt-4o-mini") - specific model
      - "GEMINI:gemini-1.5-pro"       -> ("GEMINI", "gemini-1.5-pro") - specific model
      - Case-insensitive provider names supported
    
    Args:
        s (str): Provider string in format "PROVIDER" or "PROVIDER:model"
    
    Returns:
        Tuple[str, str | None]: (provider_name, model_name_or_none)
    
    Raises:
        ValueError: If no provider is specified
    """
    if not s:
        raise ValueError("llm_model (provider) must be specified: OPENAI | GEMINI | OLLAMA[:model]")
    
    # Split on first colon to separate provider from model
    parts = s.split(":", 1)
    provider = parts[0].strip().upper()  # Normalize to uppercase
    # Extract model name if provided, otherwise None (will use handler's default)
    model = parts[1].strip() if len(parts) == 2 and parts[1].strip() else None
    return provider, model


def ai_fix(code_input: str, rule: str, message: str, llm_model: str, iterations_cc: int) -> Dict[str, Any]:
    """
    Main orchestration function that analyzes vulnerable Java code and provides secure fixes.
    
    This function coordinates the entire AI-powered security analysis workflow:
    1. Parses LLM provider and model preferences
    2. Initializes the chosen LLM handler with proper authentication
    3. Sets up document processing and vector database for CWE knowledge retrieval
    4. Runs RAG pipeline
    5. Uses CogniCrypt for iterative security verification and refinement
    6. Returns structured response with vulnerability details and secure code
    
    Args:
        code_input (str): The vulnerable Java code snippet to analyze
        rule (str): CogniCrypt rule identifier (e.g., "cognicrypt:requiredpredicateerror")  
        message (str): Error message from CogniCrypt containing rule violation details
        llm_model (str): LLM specification in format "PROVIDER" or "PROVIDER:model"
        iterations_cc (int): Maximum iterations for CogniCrypt verification refinement
    
    Returns:
        Dict[str, Any]: Structured response containing:
            - Vulnerability_name: High-level vulnerability classification
            - Explanation: Technical explanation of the issue and fix
            - CWE_references: List of relevant CWE entries with links and descriptions
            - CogniCrypt_Verified: Boolean indicating if final code passed security scan
            - Final_Secure_Code_Snippet: The verified secure replacement code
            
    Returns error dict if analysis fails:
            - error: Error message string
    """
    logger.info("Inside analysis function")

    # Parse the LLM provider string to determine which AI service to use
    provider, selected_model = _parse_provider_and_model(llm_model)
    logger.info(f"[ai_fix] Provider requested: {provider}, Model arg: {selected_model or 'None'}")
    
    # Map each provider to its corresponding API key environment variable
    if provider == "OPENAI":
        api_key_env = "OPENAI_API_KEY"
    elif provider == "GEMINI":
        api_key_env = "GOOGLE_API_KEY"  
    elif provider == "OLLAMA":
        api_key_env = None  # Ollama runs locally, no API key needed
    else:
        raise ValueError(f"Unsupported provider: {provider}")

    # Initialize the LLM handler with provider-specific configuration
    # Only pass API key for cloud providers, not for local Ollama
    handler = get_handler(
        provider,
        # Conditionally include API key only when needed (cloud providers)
        **({"api_key": os.getenv(api_key_env)} if api_key_env else {}),
        # Pass through model preference to handler's model resolution logic
        model=selected_model,
        # Low temperature
        temperature= 0.1,
    )
    logger.info(f"[ai_fix] Handler initialized for provider={provider}")

    # Initialize the core components of our analysis pipeline
    doc_processor = DocumentProcessor()      # Handles CWE document chunking and metadata
    vs_manager = VectorStoreManager()        # Manages FAISS vector database  
    rag_pipeline = RAGPipeline(doc_processor, vs_manager, handler)  # Orchestrates retrieval-augmented generation

    # Set up or load the CWE knowledge base for contextual analysis
    CWE_File_Path = r"data/CWE"
    if not os.path.exists("faiss_index"):
        # First-time setup: create vector database from CWE documents
        logger.info("Index does not exist, creating one")
        chunks = doc_processor.load_and_split(CWE_File_Path)  # Chunk CWE docs for embedding
        vs_manager.create_store(chunks)                       # Create FAISS vector store
        vs_manager.save_store()                              # Persist to disk for future use
        logger.info("Index created successfully")
    else:
        # Load existing vector database - much faster than rebuilding
        logger.info("Index exists, loading vector store")
        vs_manager.load_store()

    try:
        # === PHASE 1: RAG-based Analysis ===
        # Use retrieval-augmented generation to analyze code.
        logger.info("Starting the RAG pipeline by sending the code snippet")
        response, links, names, java_code = rag_pipeline.run(code_input, rule, message)
        # Returns: vulnerability analysis, CWE links, CWE names, initial secure Java code

        # === PHASE 2: Iterative Security Verification ===
        # Use CogniCrypt to verify and refine the generated secure code
        ccrunner = CCRUN(handler)
        final_code, verified = ccrunner.iterate_until_verified(java_code, max_iterations=iterations_cc)
        # This compiles, tests, and iteratively improves code until it passes security analysis
        
        # === PHASE 3: Final Code Processing ===  
        # Extract just the essential secure code snippet (not the full class)
        secure_snippet = handler.extract_fixed_snippet(code_input, final_code)
        
        # Generate a final technical explanation of the vulnerability and fix
        final_explanation = handler.final_explanation(code_input, final_code)

        # === PHASE 4: Response Formatting ===
        # Transform CWE links into structured format for frontend consumption
        cwe_links = [
            {
                "cwe": re.sub(r'.*/definitions/(\d+)\.html', r'CWE-\1', link),  # Extract CWE-### from URL
                "link": link   # Full URL to official CWE documentation
            }
            for link in links
        ]

        # Return comprehensive analysis results to the API caller
        logger.info("Response is returned via the API")
        return {
            "Vulnerability_name": response.vulnerability_name,        # High-level vulnerability type
            "Explanation": final_explanation,                        # Technical explanation post-verification  
            "CWE_references": cwe_links,                            # Structured CWE information with links
            "CogniCrypt_Verified": verified,                        # Boolean: did final code pass security scan?
            "Final_Secure_Code_Snippet": secure_snippet             # The verified secure replacement code
        }

    except Exception as e:
        # If any part of the analysis fails, return error information
        # This ensures the API always returns a valid response structure
        logger.error(f"Analysis failed: {str(e)}")
        return {"error": f"Analysis failed: {str(e)}"}
