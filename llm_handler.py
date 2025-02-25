# llm_handler.py
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI  # Updated import

class LLMHandler:
    def __init__(self, api_key, model="gpt-4o-mini"):
        self.llm = ChatOpenAI(openai_api_key=api_key, model=model)  # Updated to use OpenAI
        self.output_parser = StrOutputParser()
    
    def generate_query(self, user_query: str) -> str:
        """Generate optimized search query"""
        prompt = ChatPromptTemplate.from_template(
            "Generate a concise, semantically optimized search query for the code snippet {query}"
            "\n, focusing on technical terms relevant to CWE data. Output only a single-line query suitable for semantic search."
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
            - Related Document IDs: [List relevant CWE-IDs]"""
        )
        chain = prompt_template | self.llm | self.output_parser
        return chain.invoke({"context": context, "question": question})