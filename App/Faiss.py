# faiss_handler.py
import os
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.docstore.document import Document

class FAISSVectorStore:
    def __init__(self, doc_dir: str, embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"):
        self.doc_dir = doc_dir
        self.embeddings = HuggingFaceEmbeddings(model_name=embedding_model)
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200
        )
        self.vector_store = None

    def load_documents(self):
        """Load and process documents"""
        documents = []
        for filename in os.listdir(self.doc_dir):
            if filename.endswith('.txt'):
                with open(os.path.join(self.doc_dir, filename), 'r', encoding='utf-8') as f:
                    content = f.read()
                    documents.append(Document(
                        page_content=content,
                        metadata={"source": filename, "doc_id": filename[:-4]}
                    ))
        return self.text_splitter.split_documents(documents)

    def initialize_store(self):
        """Create and return FAISS index"""
        chunks = self.load_documents()
        self.vector_store = FAISS.from_documents(
            documents=chunks,
            embedding=self.embeddings
        )
        return self.vector_store

    def save_index(self, path="faiss_index"):
        """Persist index to disk"""
        self.vector_store.save_local(path)

    def load_index(self, path="faiss_index"):
        """Load existing index"""
        self.vector_store = FAISS.load_local(
            folder_path=path,
            embeddings=self.embeddings,
            allow_dangerous_deserialization=True
        )
        return self.vector_store