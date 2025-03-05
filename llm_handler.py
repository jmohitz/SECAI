from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI  # Updated import

class LLMHandler:

    def __init__(self, api_key, model="gpt-4o-mini", temperature=0.7):
        self.llm = ChatOpenAI(
            openai_api_key=api_key,
            model=model,
            temperature=temperature
        )
        self.output_parser = StrOutputParser()

    def generate_query(self, user_query: str) -> str:
        """Generate optimized search query"""
        prompt = ChatPromptTemplate.from_template(
            "Generate a concise, semantically optimized search query for the code snippet {query}"
            ",focusing on technical terms relevant to the dataset. "
            "Output only a single-line query suitable for semantic search."
        )
        chain = prompt | self.llm | self.output_parser
        return chain.invoke({"query": user_query}).strip()


    def analyze_vulnerability(self, context: str, question: str) -> str:
        """Perform vulnerability analysis using RAG"""
        prompt_template = ChatPromptTemplate.from_template(
            """ You are Java Cryptography Architecture (JCA) developer and you are tasked with
            analyzing a given code snippet and providing a secure alternate code snippet with modern standards.
            Analyse the given code snippet: {question}
            Relevant Context(includes cognicrypt violation report and rules the code violated): {context}
            
            Give you analysis and provide a secure code snippet in the following way. 
            Required Format: (Use Markdown)
            - Vulnerability Name: [Name]
            - Correct Code Snippet: give only a single line of code
            - Explanation: [120-150 words]
            """
        )
        chain = prompt_template | self.llm | self.output_parser
        return chain.invoke({"context": context, "question": question})