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

def process_analysis(json_data, code_input, rule, message):

    logger.info("Inside process_analysis")
    CWE_File_Path = r"data/CWE"
    json_string = None
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    if not OPENAI_API_KEY:
        logger.error("Error: OPENAI_API_KEY environment variable is not set. Please set it in the .env file.")
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

    logger.info("Initializing the RAG pipeline")
    rag_pipeline = RAGPipeline(doc_processor, vs_manager, llm_handler, json_string)

    logger.info("Converting the JSON file info into a string")
    if json_data:
        json_string = json.dumps(json_data, indent=2)
    else:
        json_string=None
    logger.info(f"Code Snippet : {code_input}")

    try:
        logger.info("Fetch the error type and violated CrySL rule")

        logger.info("Starting the RAG pipeline by sending the code snippet and analysis report")
        response, links, names = rag_pipeline.run(code_input, json_string, rule, message)

        cwe_links = [{"cwe": re.sub(r'.*/definitions/(\d+)\.html', r'CWE-\1', link), "name": name, "link": link} for link, name in zip(links, names)]

        # Regex pattern to capture sections based on headers at the beginning of lines.
        logger.info("Using regex to clean the response from the pipeline and separate it into 3 sections")
        pattern = r"^(Vulnerability Name|Possible Solution|Explanation):\s*([\s\S]*?)(?=^(Vulnerability Name|Possible Solution|Explanation):|$)"
        matches = re.findall(pattern, response, re.MULTILINE)
        sections = {}
        for header, content, _ in matches:
            key = header.lower().replace(" ", "_")  # Convert header to key format, e.g., "Vulnerability Name" -> "vulnerability_name"
            sections[key] = content.strip()

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
