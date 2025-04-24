from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import Runnable
from langchain_openai import ChatOpenAI
from pydantic import BaseModel
from logger_config import get_logger

logger = get_logger(__name__)

class VulnerabilityAnalysis(BaseModel):
    vulnerability_name: str
    possible_solution: str
    explanation: str

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
        snippet {code} and considering additional security context detailed in {context}. Focus solely 
        on high-level vulnerability indicators and technical terms pertinent to security analysis. Do not include any 
        CWE identifiers, Java class names, or package paths. Output the query as a single, unformatted line optimized 
        for semantic vector search."""
        )
        chain = prompt | self.llm | self.output_parser
        return chain.invoke({"code": code, "context": context}).strip()

    def analyse_vulnerability(self, context: str, question: str) -> VulnerabilityAnalysis:
        logger.info("Prompting the LLM to analyse the code snippet using all the provided context and return a "
                    "solution with explanation")
        prompt_template = ChatPromptTemplate.from_template(
            """
            You are Java Cryptography Architecture (JCA) developer and you are tasked with analyzing a given code 
            snippet and providing a secure alternate code snippet with modern standards. Analyse the given code 
            snippet: {question} Relevant Context: {context} 
            Based on this information, give your analysis, and provide a secure code snippet.
            Return only:
            Vulnerability Name: [Name]
            Possible Solution: [Few lines of code]
            Explanation: [Text explanation of the issue and the solution, around 150 words]
            
            IMPORTANT: Do not change the output format, and ensure the possible solution is always a few lines of code
            """
        )
        chain: Runnable = prompt_template | self.llm.with_structured_output(VulnerabilityAnalysis)
        return chain.invoke({"context": context, "question": question})
        # chain = prompt_template | self.llm | self.output_parser
        # return chain.invoke({"context": context, "question": question})

    def analysis_iterations(self, prev_sol: VulnerabilityAnalysis) -> VulnerabilityAnalysis:
        logger.info("Performing another analysis round with the LLM")
        prompt_template = ChatPromptTemplate.from_template(
            """
            As a Java Cryptography Architecture (JCA) developer, this is the output you provided to solve my 
            vulnerability:
            Vulnerability Name: {vulnerability_name}
            Possible Solution: {possible_solution}
            Explanation: {explanation} 
            
            Review it as a JCA expert. Improve the code and keep the same output format:
            Vulnerability Name: [Name]
            Possible Solution: [Few lines of code]
            Explanation: [Text explanation of the issue and the solution, around 150 words]
            
            IMPORTANT: Do not change the output format, and ensure the possible solution is always a few lines of code
            """
        )
        chain: Runnable = prompt_template | self.llm.with_structured_output(VulnerabilityAnalysis)
        return chain.invoke(prev_sol.model_dump())
        # chain = prompt_template | self.llm | self.output_parser
        # return chain.invoke({"prev_sol":prev_sol})