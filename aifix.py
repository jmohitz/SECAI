import os
from dotenv import load_dotenv
from document_processor import DocumentProcessor
from vector_store_manager import VectorStoreManager
from llm_handler import LLMHandler, VulnerabilityAnalysis
from rag_pipeline import RAGPipeline
import re
from typing import Dict, Any
from logger_config import get_logger

logger = get_logger(__name__)
load_dotenv()

# AI Fix function is the high level function which initializes the objects of the other classes
# It also creates or loads the vector store as needed and runs the pipeline, fetches the results
# and then creates the API response which is to be sent
def ai_fix(code_input: str, rule: str, message: str) -> Dict[str, Any]:

    logger.info("Inside analysis function")
    CWE_File_Path = r"data/CWE"
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    if not OPENAI_API_KEY:
        logger.error("Error: OPENAI_API_KEY environment variable is not set. Please set it in the .env file.")
        raise ValueError("Error: OPENAI_API_KEY environment variable is not set. Please set it in the .env file.")

    # Initializing objects for the other classes
    doc_processor = DocumentProcessor()
    vs_manager = VectorStoreManager()
    llm_handler = LLMHandler(api_key=OPENAI_API_KEY)
    rag_pipeline = RAGPipeline(doc_processor, vs_manager, llm_handler)

    # Checking if the vector stores exists, if not, it will be created
    if not os.path.exists("faiss_index"):
        logger.info("Index does not exist, creating one")
        chunks = doc_processor.load_and_split(CWE_File_Path)
        vs_manager.create_store(chunks)
        vs_manager.save_store()
        logger.info("Index created successfully")
    else:
        logger.info("Index exists, loading vector store")
        vs_manager.load_store()

    #Starting the pipeline, taking all content and returing the response
    try:
        logger.info("Starting the RAG pipeline by sending the code snippet")
        response, links, names = rag_pipeline.run(code_input, rule, message)

        cwe_links = [{"cwe": re.sub(r'.*/definitions/(\d+)\.html', r'CWE-\1', link), "name": name, "link": link} for link, name in zip(links, names)]

        logger.info("Response is returned via the API")
        return  {
                "Vulnerability_name": response.vulnerability_name,
                "Possible_solution": response.possible_solution,
                "Explanation": response.explanation,
                "CWE_references": cwe_links
                }

    except Exception as e:
        return {"error": f"Analysis failed: {str(e)}"}
