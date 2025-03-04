import os
import json
from dotenv import load_dotenv
import streamlit as st
from document_processor import DocumentProcessor
from vector_store_manager import VectorStoreManager
from llm_handler import LLMHandler
from rag_pipeline import RAGPipeline
import re

load_dotenv()
CWE_File_Path = r"data/CWE"
JSON_FILE_PATH = r"data/CryptoAnalysis-Report.json"
json_string = None

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    st.error("Error: OPENAI_API_KEY environment variable is not set. Please set it in the .env file and restart the app.")
    st.stop()

def initialize_system():
    if "rag_pipeline" not in st.session_state:

        doc_processor = DocumentProcessor()
        vs_manager = VectorStoreManager()
        llm_handler = LLMHandler(api_key=OPENAI_API_KEY)

        print("Checking for vector db index")
        if not os.path.exists("faiss_index"):
            print("Index does not exists, create one")
            chunks = doc_processor.load_and_split(CWE_File_Path)
            vs_manager.create_store(chunks)
            vs_manager.save_store()
            print("Index created")
        else:
            print("Index exists, load the vector store")
            vs_manager.load_store()
        
        st.session_state.rag_pipeline = RAGPipeline(doc_processor, vs_manager, llm_handler, json_string)

st.title("SEC-AI")
initialize_system()

if os.path.exists(JSON_FILE_PATH):
    with open(JSON_FILE_PATH, "r", encoding="utf-8") as f:
        json_data = json.load(f)
        json_string = json.dumps(json_data, indent=2)
    st.success("JSON file loaded successfully!")
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
            if json_string:
                response, links, names = st.session_state.rag_pipeline.run(code_input, json_string)
            else:
                response, links, names = st.session_state.rag_pipeline.run(code_input)
            st.markdown("---")
            st.subheader("AI Analysis:")
            st.markdown(response)
            st.markdown("---")
            st.markdown("CWE Links")
            for i in range(0, len(links)):
                c = re.sub(r".*/definitions/(\d+)\.html", r"CWE-\1", links[i])
                st.markdown(f"[{c} : {names[i]}]({links[i]})\n")
            st.markdown("---")
        except Exception as e:
            st.error(f"Error: Analysis failed: {str(e)}")