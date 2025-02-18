import os
import requests
import pandas as pd
from langchain_community.document_loaders import DirectoryLoader, UnstructuredCSVLoader
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEmbeddings  # Updated import
from langchain_community.llms import OpenAI
from langchain.chains import RetrievalQA
import streamlit as st
from PyPDF2 import PdfReader
from tqdm import tqdm

# Set up API keys
SERPAPI_API_KEY = "c71691b16625fb2aa2ddf1e21965af5b1f347a5002be16bcbd7ad92c2e491d36"  # Replace with your SerpAPI key

# Load and chunk local filesa
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
            elif filename.endswith(".csv"):
                loader = UnstructuredCSVLoader(filepath)
                csv_docs = loader.load()
                documents.extend(csv_docs)
    
    with st.spinner("Splitting documents into chunks..."):
        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=300,
            chunk_overlap=200,
            length_function=len,
            add_start_index=True,
        )
        chunks = text_splitter.split_documents(documents)
    
    return chunks

# Set up Chroma vector database
def setup_chroma(chunks: list[Document], persist_directory: str = "chroma_db") -> Chroma:
    """
    Create a Chroma vector database from the document chunks.
    """
    # Use HuggingFace Embeddings
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")  # Updated class
    db = Chroma.from_documents(chunks, embeddings, persist_directory=persist_directory)
    db.persist()
    return db

# Perform web search using SerpAPI
def web_search(query: str) -> dict:
    """
    Perform a web search using SerpAPI.
    """
    url = "https://serpapi.com/search.json"
    params = {
        "q": query,
        "api_key": SERPAPI_API_KEY,
    }
    try:
        response = requests.get(url, params=params, timeout=30)  # 10-second timeout
        return response.json()
    except requests.Timeout:
        st.error("Web search timed out. Please try again.")
        return {}

# Combine results from Chroma and web search
def combine_results(db: Chroma, query: str, web_results: dict) -> str:
    """
    Combine results from the Chroma database and web search.
    """
    # Retrieve relevant chunks from Chroma
    chroma_results = db.similarity_search(query, k=5)
    chroma_context = "\n\n".join([doc.page_content for doc in chroma_results])

    # Extract relevant information from web search
    web_context = ""
    if "organic_results" in web_results:
        for result in web_results["organic_results"]:
            web_context += f"{result['title']}\n{result['snippet']}\n\n"

    # Combine both contexts
    combined_context = f"From Local Database:\n{chroma_context}\n\nFrom Web Search:\n{web_context}"
    return combined_context

# Generate a response using OpenAI GPT
def generate_response(query: str, context: str) -> str:
    """
    Generate a response using OpenAI GPT based on the combined context.
    """
    llm = OpenAI(openai_api_key="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", temperature=0.7)  # Replace with your OpenAI API key
    prompt = f"Question: {query}\n\nContext:\n{context}\n\nAnswer:"
    response = llm(prompt)
    return response

# Build the Streamlit app
def main():
    st.title("SECAI RAG App")

    # Directory containing local files
    directory = "D:/PythonRAG/data"  # Replace with the path to your files

    st.write("Loading and chunking files...")
    chunks = load_and_chunk_files(directory)
    st.write(f"Loaded {len(chunks)} chunks.")

    st.write("Setting up Chroma database...")
    db = setup_chroma(chunks)
    st.write("Chroma database setup complete.")

    # User input
    query = st.text_input("Enter your query:")

    if query:
        st.write("Performing web search...")
        web_results = web_search(query)
        st.write("Web search complete.")

        st.write("Combining results from Chroma and web search...")
        combined_context = combine_results(db, query, web_results)
        st.write("Results combined.")

        st.write("Generating response using OpenAI GPT...")
        response = generate_response(query, combined_context)
        st.write("Response generated.")

        # Display the response
        st.write("### Response")
        st.write(response)

        # Display the combined context (for debugging)
        st.write("### Combined Context")
        st.write(combined_context)

if __name__ == "__main__":
    main()