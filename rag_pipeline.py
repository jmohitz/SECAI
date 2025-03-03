# rag_pipeline.py
import streamlit as st

class RAGPipeline:
    def __init__(self, vector_store_manager, llm_handler):
        self.vs_manager = vector_store_manager
        self.llm_handler = llm_handler

    def run(self, user_query: str):
        """Execute full RAG pipeline with separate queries for CWE and CVE"""
        # Generate separate optimized queries for CWE and CVE
        cwe_query = self.llm_handler.generate_query(user_query + " (CWE)")
        cve_query = self.llm_handler.generate_query(user_query + " (CVE)")

        st.info(f"Optimized CWE search query: {cwe_query}")
        st.info(f"Optimized CVE search query: {cve_query}")

        # Retrieve documents separately for CWE and CVE
        cwe_results = self.vs_manager.get_store("cwe").similarity_search(cwe_query, k=3)
        cve_results = self.vs_manager.get_store("cve").similarity_search(cve_query, k=3)

        # Prepare context for CWE
        cwe_context = "\n\n".join([
            f"**CWE DOCUMENT {i+1}:**\n{doc.page_content}"
            for i, doc in enumerate(cwe_results)
        ])

        # Prepare context for CVE
        cve_context = "\n\n".join([
            f"**CVE DOCUMENT {i+1}:**\n{doc.page_content}"
            for i, doc in enumerate(cve_results)
        ])

        # Combine contexts
        combined_context = f"**CWE Documents:**\n{cwe_context}\n\n**CVE Documents:**\n{cve_context}"

        # Vulnerability analysis
        analysis_result = self.llm_handler.analyze_vulnerability(combined_context, user_query)

        # Prepare document names for display
        cwe_doc_names = [doc.metadata["source"] for doc in cwe_results]
        cve_doc_names = [doc.metadata["source"] for doc in cve_results]

        # Append document names to the analysis result
        final_output = (
            f"{analysis_result}\n\n"
            f"**Retrieved CWE Documents:**\n{', '.join(cwe_doc_names)}\n\n"
            f"**Retrieved CVE Documents:**\n{', '.join(cve_doc_names)}"
        )

        return final_output

    def display_results(self, results):
        """Display search results"""
        st.subheader("FAISS Search Results")
        for i, doc in enumerate(results):
            with st.expander(f"Document {i+1} ({doc.metadata['dataset_type']}):"):
                st.write("**Content:**")
                st.write(doc.page_content)
                st.write("**Metadata:**")
                st.write(doc.metadata)