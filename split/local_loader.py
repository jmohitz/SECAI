import os
from PyPDF2 import PdfReader
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
import streamlit as st
from tqdm import tqdm

@st.cache_data
def load_and_chunk_files(directory: str) -> list[Document]:
    """
    Load and chunk documents from the specified directory.
    """
    documents = []
    files = [f for f in os.listdir(directory) if f.endswith(".pdf") or f.endswith(".csv")]

    with st.spinner("Loading files..."):
        for filename in tqdm(files, desc="Processing files"):
            filepath = os.path.join(directory, filename)
            if filename.endswith(".pdf"):
                reader = PdfReader(filepath)
                for page in reader.pages:
                    text = page.extract_text()
                    if text:
                        documents.append(Document(page_content=text, metadata={"source": filepath}))

    with st.spinner("Splitting documents into chunks..."):
        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=3000,
            chunk_overlap=200,
            length_function=len,
            add_start_index=True,
        )
        chunks = text_splitter.split_documents(documents)

    return chunks
