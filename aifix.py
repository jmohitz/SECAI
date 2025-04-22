import os
from dotenv import load_dotenv
from document_processor import DocumentProcessor
from vector_store_manager import VectorStoreManager
from llm_handler import LLMHandler
from rag_pipeline import RAGPipeline
import re
from typing import Dict, Any
from logger_config import get_logger

logger = get_logger(__name__)
load_dotenv()

def ai_fix(code_input: str, rule: str, message: str) -> Dict[str, Any]:

    logger.info("Inside analysis function")
    CWE_File_Path = r"data/CWE"
    sections = {}
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    if not OPENAI_API_KEY:
        logger.error("Error: OPENAI_API_KEY environment variable is not set. Please set it in the .env file.")
        raise ValueError("Error: OPENAI_API_KEY environment variable is not set. Please set it in the .env file.")

    doc_processor = DocumentProcessor()
    vs_manager = VectorStoreManager()
    llm_handler = LLMHandler(api_key=OPENAI_API_KEY)

    if not os.path.exists("faiss_index"):
        logger.info("Index does not exist, creating one")
        chunks = doc_processor.load_and_split(CWE_File_Path)
        vs_manager.create_store(chunks)
        vs_manager.save_store()
        logger.info("Index created successfully")
    else:
        logger.info("Index exists, loading vector store")
        vs_manager.load_store()

    logger.info("Initializing the RAG pipeline")
    rag_pipeline = RAGPipeline(doc_processor, vs_manager, llm_handler)

    try:

        logger.info("Starting the RAG pipeline by sending the code snippet")
        response, links, names = rag_pipeline.run(code_input, rule, message)
        logger.info(response)
        for i in range(0,2):
            logger.info("Initial analysis complete, now performing more iterations")
            response = llm_handler.analysis_iterations(response)
            logger.info(response)

        cwe_links = [{"cwe": re.sub(r'.*/definitions/(\d+)\.html', r'CWE-\1', link), "name": name, "link": link} for link, name in zip(links, names)]

        logger.info("Using regex to clean the response from the pipeline and separate it into 3 sections")
        pattern = r"""
        \*\*Vulnerability\s+Name:\*\*\s*(?P<vulnerability>.+?)\s*(?=\*\*Possible\s+Solution:\*\*)
        \*\*Possible\s+Solution:\*\*\s*\n(?P<solution>```java[\s\S]+?```)\s*(?=\*\*Explanation:\*\*)
        \*\*Explanation:\*\*\s*(?P<explanation>[\s\S]+)
        """

        regex = re.compile(pattern, re.VERBOSE | re.MULTILINE | re.DOTALL)
        match = regex.search(response)

        if match:
            sections = {
                "vulnerability_name": match.group("vulnerability").strip(),
                "possible_solution": match.group("solution").strip(),
                "explanation": match.group("explanation").strip()
            }
        logger.info("Response is returned via the API")

        split_response = {
            "Vulnerability_name": sections.get("vulnerability_name", ""),
            "Possible_solution": sections.get("possible_solution", ""),
            "Explanation": sections.get("explanation", ""),
            "CWE_references": cwe_links
        }
        return split_response

    except Exception as e:
        return {"error": f"Analysis failed: {str(e)}"}
