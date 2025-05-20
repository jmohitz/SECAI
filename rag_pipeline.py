import os
import re
from typing import Tuple, List
from pydantic_models.VulnerabilityAnalysis import VulnerabilityAnalysis
from logger_config import get_logger

logger = get_logger(__name__)

# RAG Pipeline class contains the run functions, whose purpose is to create the context which the LLM will use
# to analyse the code snippet. The relevant violated CrySL rule, along with the static description of the issue is
# provided as context.
# This function also performs the vector db similarity search to find the relevant CWEs using the LLM generated prompt
class RAGPipeline:
    def __init__(self, document_processor, vector_store_manager, llm_handler):
        self.document_processor = document_processor
        self.vs_manager = vector_store_manager
        self.llm = llm_handler

    def run(self, vulnerable_code: str, rule: str, message: str, iterations: int)-> Tuple[VulnerabilityAnalysis, List[str], List[str], str]:

        logger.info("Starting the run function to create context")

        CryslRules_Path = r"data/Crysl_Rules"
        ErrorDesc_Path = r"data/CogniCrypt_ErrorDesc"
        context = ""
        error_type = rule.split(":")[1]
        crysl_rule = message.split(" ")[0]
        desc_file = f"{ErrorDesc_Path}/{error_type}.json"

        # Adding the specific violated crysl rule into the context
        path = os.path.join(CryslRules_Path, crysl_rule+".txt")
        if os.path.isfile(path):
            with open(path, 'r', encoding='utf-8') as file:
                context = context + f"\n\nCrySL Rule: {crysl_rule}\n{file.read()}"

        # Adding the static error description according to crysl rule and error type into the context
        context = context+"\n\nStatic Error Descriptions\n"
        context = context +  self.document_processor.error_description_processing(desc_file, crysl_rule)
        logger.info(context)

        # Searching in the vector db to find the relevant CWE ids
        query = self.llm.build_query(vulnerable_code, context)
        logger.info(f"Optimized search query: {query}")
        results  = self.vs_manager.vector_store.similarity_search(query, k=3)
        logger.info("Vector DB search completed for relevant CWEs")
        links_list = []
        names_list = []
        for i, doc in enumerate(results):
            link = f"https://cwe.mitre.org/data/definitions/{doc.metadata['doc_id']}.html"
            name = re.search(r"Name:\s*(.+)", str(doc.page_content))
            if name:
                names_list.append(name.group(1))
                links_list.append(link)
        logger.info(f"CWE links - {links_list}\n CWE names - {names_list}")

        # Performing the vulnerability analysis via LLM
        # First the initial analysis and then more iterations to improve the solutions
        logger.info("Calling the analyse_vulnerability function which performs analysis of code snippet")
        response = self.llm.analyse_vulnerability(context, vulnerable_code)
        logger.info(vars(response))
        for i in range(0,iterations-1):
            logger.info("Initial analysis complete, now performing more iterations")
            response = self.llm.analysis_iterations(response)
            logger.info(vars(response))
        response1 = self.llm.cogniCrypt_analysis(response.possible_solution)
        logger.info(f"Generated Java class for CogniCrypt:\n{response1}")
        # Assuming response1 is the raw Java code string returned from LLM

        return response, links_list, names_list, response1
    
