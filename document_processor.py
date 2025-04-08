import json
import os
import re
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.docstore.document import Document
from logger_config import get_logger

logger = get_logger(__name__)

class DocumentProcessor:
    def __init__(self, chunk_size=1000, chunk_overlap=200):
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap
        )
    
    def load_and_split(self, doc_dir: str):
        logger.info("Splitting up the CWE files and creating metadata for using in vector DB")
        documents = []
        for filename in os.listdir(doc_dir):
            if filename.endswith('.txt'):
                with open(os.path.join(doc_dir, filename), 'r', encoding='utf-8') as f:
                    content = f.read()
                    documents.append(Document(
                        page_content=content,
                        metadata={"source": filename, "doc_id": filename[:-4]}
                    ))
        return self.text_splitter.split_documents(documents)

    def json_processing(self, json_string: str, error_type: str, crysl_rule: str):
        logger.info("Processing the analysis report JSON to filter by error type and CrySL rule")
        json_data = json.loads(json_string)
        runs = json_data.get("runs", [])
        if not runs:
            logger.error("No runs found in the JSON data")
            return []  # or handle as needed
        results = runs[0].get("results", [])
        filtered_results = [
            {
                "violatedRule": result.get("violatedRule"),
                "message": f"{result.get('message', {}).get('text', '')}\n{result.get('message', {}).get('richText', '')}"
            }
            for result in results
            if result.get("errorType", "").lower() == error_type.lower() and
            result.get("violatedRule", "").split('.')[-1].lower() == crysl_rule.lower()
        ]
        return filtered_results



    def error_description_processing(self, file_path: str, crysl_rule: str):

        error_type = file_path.split('/')[-1].split('.')[0]

        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)

        error_data = data.get(error_type, {})
        description = error_data.get("description", "")
        examples = error_data.get("examples", [])

        rule_example = next(
            (ex for ex in examples if ex["rule"].lower() == crysl_rule.lower()),
            None
        )
        misuse = rule_example.get("misuse", "") if rule_example else "No example found for this rule."
        solution = rule_example.get("solution", "") if rule_example else ""

        # Remove all HTML tags
        clean_html = lambda text: re.sub(r'<[^>]+>', '', text)
        description = clean_html(description)
        misuse = clean_html(misuse)
        solution = clean_html(solution)

        result = f"Error Type: {error_type}\n\nDescription:\n{description}\n\nExample Misuse for Rule '{crysl_rule}':\n{misuse}"
        if solution:
            result += f"\n\nSuggested Solution:\n{solution}"

        return result