# rag_pipeline.py
import os

import streamlit as st
import re

class RAGPipeline:
    def __init__(self, document_processor, vector_store_manager, llm_handler, json_string):
        self.document_processor = document_processor
        self.vs_manager = vector_store_manager
        self.llm_handler = llm_handler
        self.json_string = json_string

    def run(self, vulnerable_code: str, json_string):
        """Execute full RAG pipeline"""

        # JSON preprocessing
        CryslRules_Path = r"data/Crysl_Rules"
        context = ""
        rule_violations = {}
        list_of_violated_rules = []
        list_of_rules_information = []

        context = context+"\n\nThe violated rules and messages\n\n"
        if json_string:
            rule_violations = self.document_processor.json_processing(json_string)
        for violation in rule_violations:
            r = violation['violatedRule'].split('.')[-1]+".txt"
            if r not in list_of_violated_rules:
                list_of_violated_rules.append(r)
            context = context + f"\n\nViolated Rule: {violation['violatedRule']}\n{violation['message']}"

        context = context+"\n\nThe relevant CrySL rules\n\n"

        for rule in list_of_violated_rules:
            path = os.path.join(CryslRules_Path, rule)
            if os.path.isfile(path):
                with open(path, 'r', encoding='utf-8') as file:
                    context = context + f"\n\nCrySL Rule: {rule}\n{file.read()}"

        """        
        # Query optimization
        opt_query = self.llm_handler.generate_query(vulnerable_code)
        print(f"Optimized search query: {opt_query}")
        """

        # Document retrieval
        results = self.vs_manager.vector_store.similarity_search(vulnerable_code, k=3)
        links_list = []
        names_list = []
        for i, doc in enumerate(results):
            link = f"https://cwe.mitre.org/data/definitions/{doc.metadata["doc_id"]}.html"
            name = re.search(r"Name:\s*(.+)", str(doc.page_content))
            if name:
                names_list.append(name.group(1))
                links_list.append(link)

        # Vulnerability analysis
        return self.llm_handler.analyze_vulnerability(context, vulnerable_code), links_list, names_list