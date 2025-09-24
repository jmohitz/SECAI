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

CWE_Selection_Prompt = ChatPromptTemplate.from_template(
    """
    You are a cybersecurity expert specializing in Common Weakness Enumeration (CWE) analysis.
    
    Given the following context:
    - Vulnerable Code: {vulnerable_code}
    - CrySL Rule Context: {context}
    - Error Message: {error_message}
    
    From this list of potential CWE IDs found through static mapping and dynamic vector search:
    {candidate_cwe_ids}
    
    Select the TOP 3 most relevant CWE IDs that best match the specific vulnerability in the code.
    Consider:
    1. The exact nature of the security flaw
    2. The cryptographic context from CrySL rules
    3. The specific error patterns
    
    Output ONLY the CWE IDs separated by commas. Example: CWE-327, CWE-330, CWE-259
    No explanations, no brackets, no extra text
    
    Be selective and prioritize precision over recall.
    """
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
Explanation: [Text explanation of the issue and the solution, maximum 150 words]
IMPORTANT: Do not change the output format, and ensure the possible solution is always a few lines of code
IMPORTANT: The solution should just be the code snippet fixing the logic, do not add import statements, create
functions or try-catch blocks
Also do not add comments inside the possible solution, but integrate the logic behind them in the explanation section
"""
)

# Iterations_Prompt = ChatPromptTemplate.from_template(
# """
# As a Java Cryptography Architecture (JCA) developer, this is the output you provided
# to solve my vulnerability:

# Vulnerability Name: {vulnerability_name}
# Possible Solution: {possible_solution}
# Explanation: {explanation}

# Review it as a JCA expert. Improve the code and keep the same output format:
# Make sure to expand on the solution and improve it
# Vulnerability Name: [Name]
# Possible Solution: [Few lines of code]
# Explanation: [Text explanation of the issue and the solution, maximum 150 words]

# IMPORTANT: Do not change the output format, and ensure the possible solution is always a few lines of code
# IMPORTANT: The solution should just be the code snippet fixing the logic, do not add import statements, create
# functions or try-catch blocks
# Also do not add comments inside the possible solution, but integrate the logic behind them in the explanation section
# """
# )
CogniCrypt_Prompt = ChatPromptTemplate.from_template(
"""
You are a Java Cryptography Architecture (JCA) expert.

You had provided me with this code snippet after the user had given you an insecure code snippet. Here is a secure solution for a vulnerability you provided:
{possible_solution}

Use this logic to generate a full self-contained Java class named `Main`. 
Do NOT wrap your response in triple backticks.
Do NOT include markdown, quotes, or explanations — return only raw Java code.

Return only the valid Java source code, starting with import statements.
"""
)

SARIF_Repair_Prompt = ChatPromptTemplate.from_template(
"""
You wrote the following Java code:

{previous_code}

This code was analyzed by CogniCrypt, and the following SARIF JSON report was generated, which contains one or more security violations:

{sarif_json}

Update the code to fix all security issues described in the SARIF report.
Do not return markdown, explanations, comments, or code fences.
Return only valid Java source code (starting with `import` lines).
"""
)
ExtractSnippet_Prompt = ChatPromptTemplate.from_template(
"""
You generated this given secure code snippet after correcting the inscure code snippet given by the developer:

{original_code}

After multiple improvements with cognicrypt, you generated this final secure full Java class:

{full_java_code}

From the final code, extract only the minimal code lines that directly replace and secure the original snippet.

Return only the fixed code snippet (a few lines). 
Do NOT include import statements, class wrappers, or explanations.
Do not return markdown, explanations, comments, or code fences.
Do NOT wrap your response in triple backticks.
IMPORTANT: Do not change the output format, and ensure the possible solution is always a few lines of code
IMPORTANT: The solution should just be the code snippet fixing the logic, do not add import statements, create
functions or try-catch blocks
Return only the valid Java source snippet.
Also do not add comments inside the possible solution, but integrate the logic behind them in the explanation section
"""
)
FinalExplanation_Prompt = ChatPromptTemplate.from_template(
"""
You were given this insecure Java code snippet:

{original_code}

After applying multiple fixes and verifying it with CogniCrypt, this is the final secure version:

{final_code}

Explain the vulnerability and how the final code fixes it. Use clear, technical language, max 150 words.
Do not include the code in your answer — only return the explanation.
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

    # def analysis_iterations(self, prev_sol: VulnerabilityAnalysis) -> VulnerabilityAnalysis:
    #     logger.info("Performing another analysis round with the LLM")
    #     chain = Iterations_Prompt| self.llm.with_structured_output(VulnerabilityAnalysis)
    #     return chain.invoke(prev_sol.model_dump())
    
    def cogniCrypt_analysis(self, possible_solution: str) -> str:
        logger.info("Prompting the LLM to wrap the solution into full Java code for CogniCrypt testing")
        chain = CogniCrypt_Prompt | self.llm | self.output_parser
        return chain.invoke({"possible_solution": possible_solution}).strip()
    
    def improve_based_on_sarif(self, previous_code: str, sarif_json: str) -> str:
        logger.info("Prompting LLM to fix code using SARIF feedback from CogniCrypt")
        chain = SARIF_Repair_Prompt | self.llm | self.output_parser
        return chain.invoke({
            "previous_code": previous_code,
            "sarif_json": sarif_json
        }).strip()
    
    def extract_fixed_snippet(self, original_code: str, full_java_code: str) -> str:
        logger.info("Prompting LLM to extract final secure code snippet from full class")
        chain = ExtractSnippet_Prompt | self.llm | self.output_parser
        return chain.invoke({
            "original_code": original_code,
            "full_java_code": full_java_code
        }).strip()
    
    def final_explanation(self, original_code: str, final_code: str) -> str:
        logger.info("Prompting LLM for final explanation based on verified secure code")
        chain = FinalExplanation_Prompt | self.llm | self.output_parser
        return chain.invoke({
            "original_code": original_code,
            "final_code": final_code
        }).strip()

    def select_relevant_cwes(self, vulnerable_code: str, context: str, error_message: str, candidate_cwe_ids: list) -> list:
        """
        Use LLM to select the most relevant CWE IDs with simple parsing
        """
        logger.info(f"Prompting LLM to select most relevant CWEs from {len(candidate_cwe_ids)} candidates")
        
        cwe_list_str = ", ".join(sorted(set(candidate_cwe_ids)))
        
        chain = CWE_Selection_Prompt | self.llm | self.output_parser
        
        try:
            response = chain.invoke({
                "vulnerable_code": vulnerable_code,
                "context": context,
                "error_message": error_message,
                "candidate_cwe_ids": cwe_list_str
            }).strip()
            
            logger.info(f"LLM response: {response}")
            
            # Simple regex extraction
            import re
            cwe_matches = re.findall(r'CWE-?\d+', response, re.IGNORECASE)
            
            # Format and filter
            candidate_set = set(candidate_cwe_ids)
            selected = []
            
            for match in cwe_matches:
                cwe_id = f"CWE-{re.search(r'\d+', match).group(0)}"
                if cwe_id in candidate_set and cwe_id not in selected:
                    selected.append(cwe_id)
                    if len(selected) >= 3:
                        break
            
            if selected:
                logger.info(f"LLM selected CWEs: {selected}")
                return selected
            else:
                # Fallback
                fallback = list(sorted(candidate_set))[:3]
                logger.info(f"No valid selection, using fallback: {fallback}")
                return fallback
            
        except Exception as e:
         logger.error(f"CWE selection failed: {e}")
        return list(sorted(set(candidate_cwe_ids)))[:3]