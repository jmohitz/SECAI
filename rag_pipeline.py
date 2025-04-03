import os
import re
from typing import Optional, Dict, Any, Tuple, List
from logger_config import get_logger

logger = get_logger(__name__)

class RAGPipeline:
    def __init__(self, document_processor, vector_store_manager, llm_handler, json_string):
        self.document_processor = document_processor
        self.vs_manager = vector_store_manager
        self.llm_handler = llm_handler
        self.json_string = json_string

    def run(self, vulnerable_code: str, json_string: Optional[str], rule: str, message: str)-> Tuple[str, List[str], List[str]]:

        logger.info("Starting the run function to create context and process analysis report")

        CryslRules_Path = r"data/Crysl_Rules"
        ErrorDesc_Path = r"data/CogniCrypt_ErrorDesc"
        context = ""
        rule_violations = {}
        list_of_violated_rules = []

        error_type = rule.split(":")[1]
        crysl_rule = message.split(" ")[0]

        desc_file = f"{ErrorDesc_Path}/{error_type}.json"

        context = context+"\n\nThe violated rules and messages\n"
        if json_string:
            rule_violations = self.document_processor.json_processing(json_string, error_type, crysl_rule)
        for violation in rule_violations:
            r = violation['violatedRule'].split('.')[-1]+".txt"
            if r not in list_of_violated_rules:
                list_of_violated_rules.append(r)
            context = context + f"\n\nViolated Rule: {violation['violatedRule']}\n{violation['message']}"
        logger.info("Added the violated rules and messages from cognicrypt analysis into the LLM context")

        context = context+"\n\nThe relevant CrySL rules\n"
        for rule in list_of_violated_rules:
            path = os.path.join(CryslRules_Path, rule)
            if os.path.isfile(path):
                with open(path, 'r', encoding='utf-8') as file:
                    context = context + f"\n\nCrySL Rule: {rule}\n{file.read()}"
        logger.info("Added the relevant CrySL rules into the LLM context")

        context = context+"\n\nStatic Error Descriptions\n"
        context = context +  self.document_processor.error_description_processing(desc_file, crysl_rule)

        context = context+"\n\n\n\n"

        optimized_query = self.llm_handler.generate_query(context, vulnerable_code)
        logger.info(f"Optimized search query: {optimized_query}")

        results = self.vs_manager.vector_store.similarity_search(optimized_query, k=3)
        logger.info("Vector DB search completed for relevant CWEs")
        links_list = []
        names_list = []
        for i, doc in enumerate(results):
            link = f"https://cwe.mitre.org/data/definitions/{doc.metadata['doc_id']}.html"
            name = re.search(r"Name:\s*(.+)", str(doc.page_content))
            if name:
                names_list.append(name.group(1))
                links_list.append(link)
        logger.info("Created the links for the CWE references retrieved from DB search")

        # Vulnerability analysis
        logger.info("Calling the analyze_vulnerability function which performs analysis of code snippet")
        return self.llm_handler.analyze_vulnerability(context, vulnerable_code), links_list, names_list