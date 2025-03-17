import os
import json
from dotenv import load_dotenv
from document_processor import DocumentProcessor
from vector_store_manager import VectorStoreManager
from llm_handler import LLMHandler
from rag_pipeline import RAGPipeline
import re
import logging

logging.basicConfig(filename='aifix.log', level=logging.INFO,  format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
load_dotenv()

def process_analysis(json_data, code_input):

    logger.info("Inside process_analysis")
    CWE_File_Path = r"data/CWE"
    json_string = None
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    if not OPENAI_API_KEY:
        raise ValueError("Error: OPENAI_API_KEY environment variable is not set. Please set it in the .env file.")

    doc_processor = DocumentProcessor()
    vs_manager = VectorStoreManager()
    llm_handler = LLMHandler(api_key=OPENAI_API_KEY)

    if not os.path.exists("faiss_index"):
        logger.info("Index does not exist, creating one...")
        chunks = doc_processor.load_and_split(CWE_File_Path)
        vs_manager.create_store(chunks)
        vs_manager.save_store()
        logger.info("Index created successfully")
    else:
        logger.info("Index exists, loading vector store...")
        vs_manager.load_store()

    rag_pipeline = RAGPipeline(doc_processor, vs_manager, llm_handler, json_string)

    json_string = json.dumps(json_data, indent=2) if json_data else None

    try:
        if json_string:
            response, links, names = rag_pipeline.run(code_input, json_string)
        else:
            response, links, names = rag_pipeline.run(code_input)

        cwe_links = [{"cwe": re.sub(r'.*/definitions/(\d+)\.html', r'CWE-\1', link), "name": name, "link": link} for link, name in zip(links, names)]

        return {
            "message": "Analysis complete",
            "analysis": response,
            "cwe_references": cwe_links
        }

    except Exception as e:
        return {"error": f"Analysis failed: {str(e)}"}
