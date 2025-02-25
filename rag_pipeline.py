# rag_pipeline.py
import streamlit as st

class RAGPipeline:
    def __init__(self, vector_store_manager, llm_handler):
        self.vs_manager = vector_store_manager
        self.llm_handler = llm_handler

    def run(self, user_query: str):
        """Execute full RAG pipeline"""
        # Query optimization
        opt_query = self.llm_handler.generate_query(user_query)
        st.info(f"Optimized search query: {opt_query}")

        # Document retrieval
        results = self.vs_manager.vector_store.similarity_search(opt_query, k=3)
        
        # Prepare context
        context = "\n\n".join([
            f"**DOCUMENT {i+1}:**\n{doc.page_content}" for i, doc in enumerate(results)
        ])

        # Vulnerability analysis
        return self.llm_handler.analyze_vulnerability(context, user_query)

    def display_results(self, results):
        """Display search results"""
        st.subheader("FAISS Search Results")
        for i, doc in enumerate(results):
            with st.expander(f"Document {i+1}"):
                st.write("**Content:**")
                st.write(doc.page_content)
                st.write("**Metadata:**")
                st.write(doc.metadata)