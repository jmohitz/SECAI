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
    
    def load_and_split(self, doc_dir: str):
        """Load and split documents from directory"""
        documents = []
        for filename in os.listdir(doc_dir):
            if filename.endswith('.txt'):
                with open(os.path.join(doc_dir, filename), 'r', encoding='utf-8') as f:
                    content = f.read()
                    documents.append(Document(
                        page_content=content,
                        metadata={"source": filename, "doc_id": filename[:-4]}
                    ))
        return self.text_splitter.split_documents(documents)