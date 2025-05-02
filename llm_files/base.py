from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from pydantic_models.VulnerabilityAnalysis import VulnerabilityAnalysis
from logger_config import get_logger
logger = get_logger(__name__)

DBSearch_Prompt = ChatPromptTemplate.from_template(
"""Generate a concise, semantically enriched search query for a CWE vector database using the provided code
snippet {code} and considering additional security context detailed in {context}. Focus solely
on high-level vulnerability indicators and technical terms pertinent to security analysis. Do not include any
CWE identifiers, Java class names, or package paths. Output the query as a single, unformatted line optimized
for semantic vector search."""
)

CodeAnalysis_Prompt = ChatPromptTemplate.from_template(
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
IMPORTANT: The solution should just be the code snippet fixing the logic, do not add import statements, create
functions or try-catch blocks
Also do not add comments inside the possible solution, but integrate the logic behind them in the explanation section
"""
)

Iterations_Prompt = ChatPromptTemplate.from_template(
"""
As a Java Cryptography Architecture (JCA) developer, this is the output you provided
to solve my vulnerability:

Vulnerability Name: {vulnerability_name}
Possible Solution: {possible_solution}
Explanation: {explanation}

Review it as a JCA expert. Improve the code and keep the same output format:
Make sure to expand on the solution and improve it
Vulnerability Name: [Name]
Possible Solution: [Few lines of code]
Explanation: [Text explanation of the issue and the solution, around 150 words]

IMPORTANT: Do not change the output format, and ensure the possible solution is always a few lines of code
IMPORTANT: The solution should just be the code snippet fixing the logic, do not add import statements, create
functions or try-catch blocks
Also do not add comments inside the possible solution, but integrate the logic behind them in the explanation section
"""
)

class BaseLLM:
    def __init__(self, llm):
        self.llm           = llm
        self.output_parser = StrOutputParser()
        self.temperature   = 0.1

    def build_query(self, code: str, context: str) -> str:
        logger.info("Prompting the LLM to create an optimized search query for vector DB search")
        chain = DBSearch_Prompt | self.llm | self.output_parser
        return chain.invoke({"code": code, "context": context}).strip()

    def analyse_vulnerability(self, context: str, question: str) -> VulnerabilityAnalysis:
        logger.info("Prompting the LLM to analyse the code snippet using all the provided context and return a "
                    "solution with explanation")
        chain = CodeAnalysis_Prompt | self.llm.with_structured_output(VulnerabilityAnalysis)
        return chain.invoke({"context": context, "question": question})

    def analysis_iterations(self, prev_sol: VulnerabilityAnalysis) -> VulnerabilityAnalysis:
        logger.info("Performing another analysis round with the LLM")
        chain = Iterations_Prompt| self.llm.with_structured_output(VulnerabilityAnalysis)
        return chain.invoke(prev_sol.model_dump())
