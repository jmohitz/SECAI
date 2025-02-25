# rag_faiss.py
import os
import streamlit as st
from document_processor import DocumentProcessor
from vector_store_manager import VectorStoreManager
from llm_handler import LLMHandler
from rag_pipeline import RAGPipeline

DOC_DIR_PATH = r"D:/SECAI_RAG/data"
GEMINI_API_KEY = "AIzaSyCIaAMXZlc2iBOAR4wUtxAQG8tMoZ2XMlo"

def initialize_system():
    """Initialize all components"""
    if "rag_pipeline" not in st.session_state:
        # Initialize components
        doc_processor = DocumentProcessor()
        vs_manager = VectorStoreManager()
        llm_handler = LLMHandler(GEMINI_API_KEY)
        
        # Load and create vector store
        if not os.path.exists("faiss_index"):
            chunks = doc_processor.load_and_split(DOC_DIR_PATH)
            vs_manager.create_store(chunks)
            vs_manager.save_store()
        else:
            vs_manager.load_store()
        
        # Create pipeline
        st.session_state.rag_pipeline = RAGPipeline(vs_manager, llm_handler)

# Streamlit UI
st.title("SEC-AI")
initialize_system()

code_input = st.text_area(
    "Input code snippet for analysis:",
    height=200,
    placeholder="Paste your code here..."
)

if st.button("Analyze Code", type="primary"):
    with st.spinner("Analyzing potential vulnerabilities..."):
        try:
            response = st.session_state.rag_pipeline.run(code_input)
            st.markdown("---")
            st.subheader("AI Analysis:")
            st.markdown(response)
        except Exception as e:
            st.error(f"Error: Analysis failed: {str(e)}")