# rag_faiss.py
import os
import json
from dotenv import load_dotenv
import streamlit as st
from document_processor import DocumentProcessor
from vector_store_manager import VectorStoreManager
from llm_handler import LLMHandler
from rag_pipeline import RAGPipeline

# Load environment variables from .env file
load_dotenv()

DOC_DIR_PATH = r"SECAI/data"
DATASET_TYPES = ["cwe", "cve"]  # List of dataset types
JSON_FILE_PATH = r"SECAI/data/CryptoAnalysis-Report.json"  # Path to the JSON file

# Read API key from environment variable
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    st.error("Error: OPENAI_API_KEY environment variable is not set. Please set it in the .env file and restart the app.")
    st.stop()

def initialize_system():
    """Initialize all components"""
    if "rag_pipeline" not in st.session_state:
        vs_manager = VectorStoreManager()
        
        # Initialize LLMHandler (default parameters are defined in LLMHandler)
        llm_handler = LLMHandler(api_key=OPENAI_API_KEY)

        # Initialize vector stores for all datasets
        for dataset_type in DATASET_TYPES:
            if not vs_manager.index_exists(dataset_type):
                doc_processor = DocumentProcessor()
                print(f"load and split started, {dataset_type}")
                chunks = doc_processor.load_and_split(DOC_DIR_PATH, dataset_type)
                print(f"load and split done, {dataset_type}")
                vs_manager.create_store(chunks, dataset_type)
                print(f"store created, {dataset_type}")
            else:
                print(f"index exists, {dataset_type}")
                vs_manager.load_store(dataset_type)
        
        # Create pipeline
        st.session_state.rag_pipeline = RAGPipeline(vs_manager, llm_handler)

# Streamlit UI
st.title("SEC-AI")
initialize_system()

# Load JSON file
json_string = None
if os.path.exists(JSON_FILE_PATH):
    with open(JSON_FILE_PATH, "r", encoding="utf-8") as f:
        json_data = json.load(f)
        json_string = json.dumps(json_data, indent=2)  # Convert JSON to string
    st.success("JSON file loaded successfully!")
    st.json(json_data)  # Display the JSON content in the app
else:
    st.warning(f"JSON file not found at: {JSON_FILE_PATH}")

code_input = st.text_area(
    "Input code snippet for analysis:",
    height=200,
    placeholder="Paste your code here..."
)

if st.button("Analyze Code", type="primary"):
    with st.spinner("Analyzing potential vulnerabilities..."):
        try:
            # Pass the JSON string to the LLM along with the code input
            if json_string:
                response = st.session_state.rag_pipeline.run(code_input, json_string)
            else:
                response = st.session_state.rag_pipeline.run(code_input)

            st.markdown("---")
            st.subheader("AI Analysis:")
            st.markdown(response)
        except Exception as e:
            st.error(f"Error: Analysis failed: {str(e)}")