import os
from dotenv import load_dotenv
from document_processor import DocumentProcessor
from vector_store_manager import VectorStoreManager
from llm_files import get_handler
from rag_pipeline import RAGPipeline
import re
from typing import Dict, Any
from logger_config import get_logger
from ccrun import CCRUN

logger = get_logger(__name__)
load_dotenv()


# AI Fix function is the high level function which initializes the objects of the other classes
# It also creates or loads the vector store as needed and runs the pipeline, fetches the results
# and then creates the API response which is to be sent
def ai_fix(code_input: str, rule: str, message: str, llm_model: str, iterations_cc: int) -> Dict[str, Any]:
    logger.info("Inside analysis function")
    handler = get_handler(llm_model,
        api_key=os.getenv("OPENAI_API_KEY" if llm_model.upper() == "OPENAI" else "GOOGLE_API_KEY"),
        temperature=0.1
    )

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


        cwe_links = [{"cwe": re.sub(r'.*/definitions/(\d+)\.html', r'CWE-\1', link), "name": name, "link": link} for
                     link, name in zip(links, names)]

        logger.info("Response is returned via the API")
        return {
            "Vulnerability_name": response.vulnerability_name,
            #"Possible_solution": response.possible_solution,
            "Explanation": final_explanation,
            "CWE_references": cwe_links,
            "CogniCrypt_Verified": verified,
            "Final_Secure_Code_Snippet": secure_snippet
        }

    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        return {"error": f"Analysis failed: {str(e)}"}

