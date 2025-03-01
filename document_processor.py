# document_processor.py
import os
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.docstore.document import Document

class DocumentProcessor:
    def __init__(self, chunk_size=1000, chunk_overlap=200):
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap
        )
    
    def load_and_split(self, doc_dir: str, dataset_type: str):
        """Load and split documents from directory for a specific dataset"""
        documents = []
        dataset_dir = os.path.join(doc_dir, dataset_type)  # Subfolder for the dataset
        if not os.path.exists(dataset_dir):
            raise FileNotFoundError(f"Dataset directory not found: {dataset_dir}")

        for filename in os.listdir(dataset_dir):
            if filename.endswith('.txt'):
                with open(os.path.join(dataset_dir, filename), 'r', encoding='utf-8') as f:
                    content = f.read()
                    documents.append(Document(
                        page_content=content,
                        metadata={"source": filename, "doc_id": filename[:-4], "dataset_type": dataset_type}
                    ))
                print(filename)
        return self.text_splitter.split_documents(documents)