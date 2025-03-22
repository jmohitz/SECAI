from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
import logging

logging.basicConfig(filename='aifix.log', level=logging.INFO,  format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class LLMHandler:

    def __init__(self, api_key, model="gpt-4o-mini", temperature=0.7):
        self.llm = ChatOpenAI(
            openai_api_key=api_key,
            model=model,
            temperature=temperature
        )
        self.output_parser = StrOutputParser()

    def generate_query(self, violations: str, code: str) -> str:

        logger.info("Prompting the LLM to create an optimized search query for vector DB search")
        prompt = ChatPromptTemplate.from_template(
        """
        Generate a concise, semantically optimized search query for the code snippet {code}
        and take into account the possible violations of rules from {violations}
        focusing on technical terms relevant to the dataset.
        Do not include:
            CWE identifiers (e.g., CWE-327)
            Java class or package names (e.g., javax.crypto.*)
        Format the output as a single line, optimized for semantic vector search.
        """
        )
        chain = prompt | self.llm | self.output_parser
        return chain.invoke({"code": code, "violations": violations}).strip()


    def analyze_vulnerability(self, context: str, question: str) -> str:

        logger.info("Prompting the LLM to analyse the code snippet using all the provided context and return a "
                    "solution with explanation")
        prompt_template = ChatPromptTemplate.from_template(
            """ You are Java Cryptography Architecture (JCA) developer and you are tasked with
            analyzing a given code snippet and providing a secure alternate code snippet with modern standards.
            Analyse the given code snippet: {question}
            Relevant Context(includes cognicrypt violation report and rules the code violated): {context}
            Based on this information, give your analysis, and provide a secure code snippet using the following format:
            (Do not use markdown or other formatting tools)
            Vulnerability Name: [Name]
            Possible Solution: [give me 1 or maximum 2 lines of code here]
            Explanation: [around 100 words]
            """
        )
        chain = prompt_template | self.llm | self.output_parser
        return chain.invoke({"context": context, "question": question})