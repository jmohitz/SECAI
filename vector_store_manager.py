# vector_store_manager.py
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings
import os

class VectorStoreManager:
    def __init__(self, embedding_model="sentence-transformers/all-MiniLM-L6-v2"):
        self.embeddings = HuggingFaceEmbeddings(model_name=embedding_model)
        self.vector_stores = {}  # Dictionary to store multiple vector stores
        self.base_index_path = r"SECAI/faiss_index"  # Base folder for all indices

    def get_index_path(self, dataset_type):
        """Get the index path for a specific dataset type"""
        return os.path.join(self.base_index_path, dataset_type)

    def index_exists(self, dataset_type):
        """Check if FAISS index files exist for a specific dataset"""
        index_path = self.get_index_path(dataset_type)
        required_files = ["index.faiss", "index.pkl"]
        return all(os.path.exists(os.path.join(index_path, file)) for file in required_files)

    def create_store(self, documents, dataset_type):
        """Create new FAISS index for a specific dataset"""
        index_path = self.get_index_path(dataset_type)
        print(f"creating_store, {dataset_type}")
        os.makedirs(index_path, exist_ok=True)  # Create directory if it doesn't exist
        self.vector_stores[dataset_type] = FAISS.from_documents(
            documents=documents,
            embedding=self.embeddings
        )
        self.save_store(dataset_type)
        return self.vector_stores[dataset_type]

    def save_store(self, dataset_type):
        """Persist index to disk for a specific dataset"""
        index_path = self.get_index_path(dataset_type)
        self.vector_stores[dataset_type].save_local(index_path)

    def load_store(self, dataset_type):
        """Load existing index for a specific dataset"""
        index_path = self.get_index_path(dataset_type)
        self.vector_stores[dataset_type] = FAISS.load_local(
            folder_path=index_path,
            embeddings=self.embeddings,
            allow_dangerous_deserialization=True
        )
        return self.vector_stores[dataset_type]

    def get_store(self, dataset_type):
        """Get the vector store for a specific dataset"""
        return self.vector_stores.get(dataset_type)