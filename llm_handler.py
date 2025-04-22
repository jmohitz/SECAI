from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from logger_config import get_logger

logger = get_logger(__name__)

class LLMHandler:

    def __init__(self, api_key, model="gpt-4o-mini", temperature=0.1):
        self.llm = ChatOpenAI(
            openai_api_key=api_key,
            model=model,
            temperature=temperature
        )
        self.output_parser = StrOutputParser()

    def generate_query(self, context: str, code: str) -> str:

        logger.info("Prompting the LLM to create an optimized search query for vector DB search")
        prompt = ChatPromptTemplate.from_template(
        """Generate a concise, semantically enriched search query for a CWE vector database using the provided code 
        snippet ({code}) and considering additional security context detailed in ({context}). Focus solely 
        on high-level vulnerability indicators and technical terms pertinent to security analysis. Do not include any 
        CWE identifiers, Java class names, or package paths. Output the query as a single, unformatted line optimized 
        for semantic vector search."""
        )
        chain = prompt | self.llm | self.output_parser
        return chain.invoke({"code": code, "context": context}).strip()


    def analyze_vulnerability(self, context: str, question: str) -> str:

        logger.info("Prompting the LLM to analyse the code snippet using all the provided context and return a "
                    "solution with explanation")
        prompt_template = ChatPromptTemplate.from_template(
            """You are Java Cryptography Architecture (JCA) developer and you are tasked with analyzing a given code 
            snippet and providing a secure alternate code snippet with modern standards. Analyse the given code 
            snippet: {question} Relevant Context: {context} Based on this information, give your analysis, 
            and provide a secure code snippet using the following format: (Do not use markdown or other formatting 
            tools) Vulnerability Name: [Name] Possible Solution: [Use the generated explanation and additional 
            context to provide a solution in very few lines of code] [Make the solution a line of code, 
            not text explanation] Explanation: [around 150 words]"""
        )
        chain = prompt_template | self.llm | self.output_parser
        return chain.invoke({"context": context, "question": question})

    def analysis_iterations(self, prev_sol:str):
        logger.info("Performing another analysis round with the LLM")
        prompt_template = ChatPromptTemplate.from_template(
            """As a Java Cryptography Architecture (JCA) developer, this is the output you provided to solve my 
            vulnerability. Here is the previous solution: {prev_sol}. Check this solution and provide improvements to 
            the code using the same format as before. Always stick to the same output format, Vulnerability Name, 
            Possible Solution and Explanation as the sections. Keep the solution to a few lines of code, 
            do not create class or method for that but give the lines of code"""
        )
        chain = prompt_template | self.llm | self.output_parser
        return chain.invoke({"prev_sol":prev_sol})