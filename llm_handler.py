# llm_handler.py
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

class LLMHandler:
    def __init__(self, api_key, model="gpt-4", temperature=0.7, top_p=50, max_tokens=150):
        """
        Initialize LLMHandler with configurable parameters.

        :param api_key: OpenAI API key
        :param model: Model name (default: "gpt-4")
        :param temperature: Sampling temperature (default: 0.7)
        :param top_k: Top-k sampling (default: 50)
        :param max_tokens: Maximum number of tokens in the output (default: 150)
        """
        self.llm = ChatOpenAI(
            openai_api_key=api_key,
            model=model,
            temperature=temperature,
            top_p=top_p,
            max_tokens=max_tokens
        )
        self.output_parser = StrOutputParser()
    
    def generate_query(self, user_query: str) -> str:
        """Generate optimized search query for a specific dataset"""
        prompt = ChatPromptTemplate.from_template(
            "Generate a concise, semantically optimized search query for the code snippet {query}"
            "\n, focusing on technical terms relevant to the dataset. Output only a single-line query suitable for semantic search."
        )
        chain = prompt | self.llm | self.output_parser
        return chain.invoke({"query": user_query}).strip()
    
    def analyze_vulnerability(self, context: str, question: str) -> str:
        """Perform vulnerability analysis using RAG"""
        prompt_template = ChatPromptTemplate.from_template(
            """As a Security expert, analyze the code snippet using the context:
            **Relevant Context**: {context}
            **Vulnerable Code**: {question}
            Required Format: (Use Markdown)
            - Vulnerability Name: [Name]
            - Correct Code Snippet: [Java]
                [secure code]
            - Technical Explanation: [120-150 words]
            - Related Document IDs: [List relevant CWE-IDs]
            In place of the relevant documents IDs, list the clickable links to these CWE ID pages. To do that
            use the format https://cwe.mitre.org/data/definitions/ID_no.html 
            and replace ID_no with the number of the CWE ID
            """
        )
        chain = prompt_template | self.llm | self.output_parser
        return chain.invoke({"context": context, "question": question})