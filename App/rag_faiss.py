# Requirements:
# pip install langchain-openai faiss-cpu beautifulsoup4 tiktoken streamlit sentence-transformers langchain-huggingface

import os
import streamlit as st
from Faiss import FAISSVectorStore
from langchain.docstore.document import Document
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI



# API Keys (replace with your actual key)
openai_api_key = "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"

# Initialize components
llm = ChatOpenAI(model="gpt-4", temperature=0.5, openai_api_key=openai_api_key)


DOC_DIR_PATH = "D:/PythonRAG/data/"

def prepare_faiss_db():
    """Prepare FAISS vector store using the handler class"""
    if "vector_store" not in st.session_state:
        try:
            faiss_handler = FAISSVectorStore(DOC_DIR_PATH)
            st.session_state.vector_store = faiss_handler.initialize_store()
            faiss_handler.save_index()  # Optional: Save index for future sessions
            st.success("Vector store initialized successfully")
        except Exception as e:
            st.error(f"Initialization failed: {str(e)}")
            st.stop()


def generate_query(user_query: str) -> str:
    """Generate optimized query for semantic search"""
    prompt = ChatPromptTemplate.from_template(
        "Generate a concise, semantically optimized search query for the code snippet {query}"
        "\n, focusing on technical terms relevant to CWE data. Output only a single-line query suitable for semantic search."
    )
    chain = prompt | llm | StrOutputParser()
    raw_query = chain.invoke({"query": user_query})
    return raw_query.strip()  # Explicit whitespace stripping

def rag_pipeline(user_query: str):
    """Main RAG workflow"""
    if "vector_store" not in st.session_state:
        st.error("Database not initialized!")
        return
    
    # Generate and display optimized query
    opt_query = generate_query(user_query)
    st.info(f"Optimized search query: {opt_query}")
    
    # Retrieve relevant documents
    results = st.session_state.vector_store.similarity_search(opt_query, k=3)
    print(results)
    # Prepare context with document IDs
    context = "\n\n".join([
        f"DOCUMENT {doc.metadata['doc_id']}:\n{doc.page_content}"
        for doc in results
    ])
    
    # Generate formatted response
    prompt_template = ChatPromptTemplate.from_template(
        """As a cybersecurity expert, analyze this code vulnerability using the context:
        
        **Vulnerable Code**:
        {question}
        
        **Relevant Context**:
        {context}
        
        **Required Format**:
        - Vulnerability Name
        - Secure Code Solution
        - Correct Code snippet 
        - Technical Explanation (120-150 words)
        - Related Document IDs (read)
       """
    )
    
    chain = prompt_template | llm | StrOutputParser()
    return chain.invoke({
        "context": context,
        "question": user_query
    })

# Initialize FAISS store
if "vector_store" not in st.session_state:
    with st.spinner("Initializing security database..."):
        prepare_faiss_db()

st.title("SEC-AI")

code_input = st.text_area(
    "Input code snippet for analysis:",
    height=200,
    placeholder="Paste your code here..."
)

if st.button("Analyze Code", type="primary"):
    with st.spinner("Analyzing potential vulnerabilities..."):
        try:
            response = rag_pipeline(code_input)
            st.markdown("---")
            st.subheader("AI Analysis:")
            st.markdown(response)
        except Exception as e:
            st.error(f"Analysis failed: {str(e)}")