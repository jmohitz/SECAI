from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings

class VectorStoreManager:
    def __init__(self, embedding_model="sentence-transformers/all-MiniLM-L6-v2"):
        self.embeddings = HuggingFaceEmbeddings(model_name=embedding_model)
        self.vector_store = None

    def create_store(self, documents):
        """Create new FAISS index"""
        self.vector_store = FAISS.from_documents(
            documents=documents,
            embedding=self.embeddings
        )
        return self.vector_store

    def save_store(self, path="faiss_index"):
        """Persist index to disk"""
        self.vector_store.save_local(path)

    def load_store(self, path="faiss_index"):
        """Load existing index"""
        self.vector_store = FAISS.load_local(
            folder_path=path,
            embeddings=self.embeddings,
            allow_dangerous_deserialization=True
        )
        return self.vector_store