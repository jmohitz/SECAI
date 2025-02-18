from langchain_community.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEmbeddings  # Updated import
from langchain_core.documents import Document

def setup_chroma(chunks: list[Document], persist_directory: str = "chroma_db") -> Chroma:
    """
    Create a Chroma vector database from the document chunks.
    """
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")  # Updated class
    db = Chroma.from_documents(chunks, embeddings, persist_directory=persist_directory)
    db.persist()
    return db
