import os
import re
import pandas as pd
from typing import Tuple, List, Set
from logger_config import get_logger
from pydantic_models.VulnerabilityAnalysis import VulnerabilityAnalysis

logger = get_logger(__name__)

# CSV path for Excel-based CWE mapping
CSV_PATH = "CWE_Mapping/CWE_Mapping.csv"

class CWEMapper:
    def __init__(self):
        try:
            if not os.path.exists(CSV_PATH):
                raise FileNotFoundError(f"CWE mapping file not found: {CSV_PATH}")
            
            self.mapping_df = pd.read_csv(CSV_PATH)
            
            # Validate required columns
            required_columns = ["CrySL File", "CWE-ID(s)"]
            missing_columns = [col for col in required_columns if col not in self.mapping_df.columns]
            if missing_columns:
                raise ValueError(f"Missing required columns in CSV: {missing_columns}")
            
            self.mapping_df.fillna("", inplace=True)
            logger.info(f"Loaded CWE mapping from {CSV_PATH} with {len(self.mapping_df)} rows.")
            
        except Exception as e:
            logger.error(f"Failed to initialize CWE mapper: {e}")
            raise

    def get_static_cwe_ids(self, crysl_rule: str) -> Set[str]:
        logger.debug(f"Looking up static CWE IDs for CrySL rule: {crysl_rule}")
        
        # Add .crysl extension if not present
        rule_filename = crysl_rule if crysl_rule.endswith('.crysl') else f"{crysl_rule}.crysl"
        
        # Filter by CrySL File column (FIXED)
        filtered = self.mapping_df[
            self.mapping_df["CrySL File"].str.strip().str.lower() == rule_filename.strip().lower()
        ]
        
        cwe_ids = set()
        for _, row in filtered.iterrows():
            cwe = row["CWE-ID(s)"]  # FIXED: Use correct column name
            if pd.notna(cwe):
                # Handle both single CWE-IDs and comma-separated lists
                cwe_ids.update([c.strip() for c in str(cwe).split(",") if c.strip()])
        
        if cwe_ids:
            logger.info(f"Static CWE IDs found for {crysl_rule}: {cwe_ids}")
        else:
            logger.warning(f"No static CWE IDs found for {crysl_rule}")
        
        return cwe_ids

class RAGPipeline:
    def __init__(self, document_processor, vector_store_manager, llm_handler):
        self.document_processor = document_processor
        self.vs_manager = vector_store_manager
        self.llm = llm_handler

    def run(self, vulnerable_code: str, rule: str, message: str) -> Tuple[VulnerabilityAnalysis, List[str], List[str], str]:
        logger.info("Starting the run function to create context")
        
        CryslRules_Path = r"data/Crysl_Rules"
        ErrorDesc_Path = r"data/CogniCrypt_ErrorDesc"
        
        context = ""
        error_type = rule.split(":")[1].split("_")[0]
        crysl_rule = rule.split("_")[1]
        desc_file = f"{ErrorDesc_Path}/{error_type}.json"

        # Load CrySL rule file
        rule_path = os.path.join(CryslRules_Path, crysl_rule + ".txt")
        if os.path.isfile(rule_path):
            with open(rule_path, 'r', encoding='utf-8') as file:
                context += f"\n\nCrySL Rule: {crysl_rule}\n{file.read()}"

        # Add static error description
        context += "\n\nStatic Error Descriptions\n"
        context += self.document_processor.error_description_processing(desc_file, crysl_rule)
        logger.info("Context built successfully")

        # RAG search query
        query = self.llm.build_query(vulnerable_code, context)
        logger.info(f"Optimized search query: {query}")

        results = self.vs_manager.vector_store.similarity_search(query, k=3)
        logger.info("Vector DB search completed for relevant CWEs")

        # Load static CWE IDs from Excel/CSV
        try:
            cwe_mapper = CWEMapper()
            static_cwe_ids = cwe_mapper.get_static_cwe_ids(crysl_rule)
            logger.info(f"Successfully loaded {len(static_cwe_ids)} static CWE IDs from Excel")
        except Exception as e:
            logger.error(f"Failed to retrieve static CWE IDs for '{crysl_rule}': {e}")
            static_cwe_ids = set()

        # Extract dynamic CWE IDs and doc content from vector DB
        dynamic_cwe_ids = set()
        cwe_doc_map = {}
        for doc in results:
            doc_id = str(doc.metadata.get("doc_id"))
            if doc_id:
                dynamic_cwe_ids.add(f"CWE-{doc_id}")
                cwe_doc_map[doc_id] = doc.page_content

        logger.info(f"Dynamic CWE IDs from vector DB: {dynamic_cwe_ids}")
        logger.info(f"Static CWE IDs from Excel: {static_cwe_ids}")

                # Combine static + dynamic with proper formatting
        combined_cwe_ids = set()
        
        # Add static CWE IDs (ensure CWE- prefix)
        for cwe in static_cwe_ids:
            formatted_cwe = cwe if cwe.startswith("CWE-") else f"CWE-{cwe}"
            combined_cwe_ids.add(formatted_cwe)
        
        # Add dynamic CWE IDs
        combined_cwe_ids.update(dynamic_cwe_ids)

        logger.info(f"Combined CWE candidates for '{crysl_rule}': {combined_cwe_ids}")
        logger.info(f"Pipeline statistics - Static CWEs: {len(static_cwe_ids)}, "
                   f"Dynamic CWEs: {len(dynamic_cwe_ids)}, "
                   f"Total unique CWEs: {len(combined_cwe_ids)}")

        # NEW: Use LLM to select most relevant CWE IDs
        if combined_cwe_ids:
            selected_cwe_ids = self.llm.select_relevant_cwes(
                vulnerable_code=vulnerable_code,
                context=context,
                error_message=message,
                candidate_cwe_ids=list(combined_cwe_ids)
            )
            logger.info(f"LLM selected top relevant CWEs: {selected_cwe_ids}")
        else:
            selected_cwe_ids = []
            logger.warning("No CWE candidates found for LLM selection")

        # Build links and names list from LLM-selected CWEs
        links_list = []
        names_list = []

        for cwe_id in selected_cwe_ids:
            cwe_num = cwe_id.replace("CWE-", "").strip()
            link = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
            links_list.append(link)

        logger.info(f"Generated {len(links_list)} CWE links from LLM selection")


            # Try to extract name from vector DB match
            # name = None
            # if cwe_num in cwe_doc_map:
            #     match = re.search(r"Name:\s*(.+)", str(cwe_doc_map[cwe_num]))
            #     if match:
            #         name = match.group(1).strip()
            
            # names_list.append(name if name else f"{cwe_id} (name unavailable)")

        logger.info(f"CWE links - {links_list}")

        # Vulnerability analysis
        logger.info("Calling the analyse_vulnerability function which performs analysis of code snippet")
        response = self.llm.analyse_vulnerability(context, vulnerable_code)
        logger.info("Vulnerability analysis completed")
        logger.info(vars(response))

        # Secure Java generation
        response1 = self.llm.cogniCrypt_analysis(response.possible_solution)
        logger.info(f"Generated Java class for CogniCrypt:\n{response1}")

        # Final return (unchanged)
        return response, links_list, names_list, response1
