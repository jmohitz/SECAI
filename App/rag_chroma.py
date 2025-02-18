# Requirements:
# pip install langchain-openai faiss-cpu beautifulsoup4 tiktoken streamlit sentence-transformers langchain-huggingface

import os
import streamlit as st
from langchain.docstore.document import Document
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS
from langchain.text_splitter import RecursiveCharacterTextSplitter

######################
# API Keys and Components
######################

# API Keys (replace with your actual key)
openai_api_key = "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"

# Initialize components
llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0.7, openai_api_key=openai_api_key)
embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")

###############################
# Document Dataset Integration Code
###############################

DOC_DIR_PATH = "D:/PythonRAG/data/"

def load_documents(directory_path: str) -> list:
    """Load all content from text files as separate documents."""
    documents = []
    for filename in os.listdir(directory_path):
        if filename.endswith('.txt'):
            filepath = os.path.join(directory_path, filename)
            with open(filepath, 'r', encoding='utf-8') as file:
                content = file.read()
            doc_id = os.path.splitext(filename)[0]
            doc = Document(page_content=content, metadata={"doc_id": doc_id})
            documents.append(doc)
    return documents

def prepare_faiss_db():
    """Prepare FAISS vector store with local documents."""
    docs = load_documents(DOC_DIR_PATH)
    if not docs:
        st.error("No documents found! Check your directory path.")
        return
    
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
    docs_split = text_splitter.split_documents(docs)
    
    st.session_state.vector_store = FAISS.from_documents(docs_split, embeddings)
    st.success("Documents successfully loaded from local text files")

###############################
# RAG Pipeline Functions 
###############################

def generate_query(user_query: str) -> str:
    """Generate optimized query for semantic search."""
    prompt = ChatPromptTemplate.from_template(
        "Generate an optimized search query for semantic search based on: {query}"
        "\nFocus on key concepts and synonyms. Output only the query."
    )
    chain = prompt | llm | StrOutputParser()
    return chain.invoke({"query": user_query})

def rag_pipeline(user_query: str):
    """Main RAG pipeline."""
    if "vector_store" not in st.session_state:
        st.error("Document database not initialized!")
        return
    
    opt_query = generate_query(user_query)
    st.info(f"Generated optimized query: {opt_query}")
    
    faiss_results = st.session_state.vector_store.similarity_search(opt_query, k=2)
    
    combined_context = [f"FAISS RESULT: {doc.page_content}" for doc in faiss_results]
    
    prompt = ChatPromptTemplate.from_template(
        """You are a cybersecurity expert analyzing code vulnerabilities. Given:
    1. A vulnerable code snippet
    2. FAISS search results containing relevant information

Respond using this exact template format:

**Error Code**: {question}

**Solution**: 
[Secure alternative code]

**Explanation**: 
[100-150 word technical explanation of vulnerability and fix. Mention specific cryptographic principles/risks]

**Related Document IDs**: 
[Document IDs from FAISS results (comma-separated)]

Use this context:
{context}
"""
    )
    
    chain = prompt | llm | StrOutputParser()
    return chain.invoke({
        "context": "\n\n".join(combined_context),
        "question": user_query
    })

###############################
# Streamlit App Interface
###############################

if "db_initialized" not in st.session_state:
    with st.spinner("Loading local documents..."):
        try:
            prepare_faiss_db()
            st.session_state["db_initialized"] = True
        except Exception as e:
            st.error(f"Failed to initialize document database: {str(e)}")
            st.stop()

st.title("Security Analyzer")
st.markdown("**Vulnerability Analysis System**")

st.header("Code Analysis")
code_input = st.text_area("Paste vulnerable code snippet:", height=150)

if st.button("Analyze Code"):
    with st.spinner("Analyzing vulnerabilities..."):
        response = rag_pipeline(code_input)
    st.subheader("Security Analysis Report")
    st.markdown(response)