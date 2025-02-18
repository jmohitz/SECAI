import streamlit as st
from app.local_loader import load_and_chunk_files
from app.chroma_db import setup_chroma
from app.web_search import web_search
from app.utils import combine_results
from app.gpt_response import generate_response

def main():
    st.title("SECAI RAG App")

    # Directory containing local files
    directory = "D:/PythonRAG/data"  # Replace with your directory path

    st.write("Loading and chunking files...")
    chunks = load_and_chunk_files(directory)
    st.write(f"Loaded {len(chunks)} chunks.")

    st.write("Setting up Chroma database...")
    db = setup_chroma(chunks)
    st.write("Chroma database setup complete.")

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

        st.write("### Response")
        st.write(response)

        st.write("### Combined Context")
        st.write(combined_context)

if __name__ == "__main__":
    main()
