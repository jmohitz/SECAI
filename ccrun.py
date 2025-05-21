import subprocess
import os
from pydantic_models.VulnerabilityAnalysis import VulnerabilityAnalysis
from llm_files import get_handler
from logger_config import get_logger
from typing import Tuple
import json


logger = get_logger(__name__)

class CCRUN:
    def __init__(self, llm_handler):
        self.llm = llm_handler
    
    def sarif_has_violations(self, path: str) -> bool:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return len(data["runs"][0].get("results", [])) > 0


    def iterate_until_verified(self, initial_solution: str, max_iterations: int = 5) -> Tuple[str, bool]:
        current_solution = initial_solution

        for i in range(max_iterations):
            logger.info(f" Iteration {i + 1} - Saving, compiling, and analyzing Java code")

            # Step 1: Save code
            java_path = save_llm_output(current_solution, "Main.java")
            logger.info(f"[Iteration {i + 1}]  Java code saved to {java_path}")

            # Step 2: Compile code
            try:
                class_path = compile_java(java_path)
                logger.info(f"[Iteration {i + 1}]  Compilation succeeded: {class_path}")
            except Exception as e:
                logger.error(f"[Iteration {i + 1}]  Compilation failed: {str(e)}")
                raise

            # Step 3: Package into .jar
            try:
                jar_path = convert_to_jar(class_path)
                logger.info(f"[Iteration {i + 1}]  JAR file created at: {jar_path}")
            except Exception as e:
                logger.error(f"[Iteration {i + 1}]  JAR creation failed: {str(e)}")
                raise

            # Step 4: Run CogniCrypt analysis
            sarif_path = r"GeneratedCode/CryptoAnalysis-Report.json"
            logger.info(f"[Iteration {i + 1}]  Running CogniCrypt...")
            run_cognicrypt(
                scanner_jar_path=r"CCJar/HeadlessJavaScanner-4.2.1-jar-with-dependencies.jar",
                app_jar_path=jar_path,
                rules_dir=r"JCA-CrySL-rules",
                report_path=sarif_path,
                report_format="SARIF"
            )

            # Step 5: Check SARIF results
            if not self.sarif_has_violations(sarif_path):
                logger.info(f"[Iteration {i + 1}]  No violations found CogniCrypt verification successful")
                return current_solution, True

            logger.info(f"[Iteration {i + 1}]  Violations detected — passing SARIF to LLM for refinement")

            with open(sarif_path, "r", encoding="utf-8") as f:
                sarif_json = f.read()

            # Step 6: Refine with LLM
            current_solution = self.llm.improve_based_on_sarif(
                previous_code=current_solution,
                sarif_json=sarif_json
            )
            logger.info(f"[Iteration {i + 1}]  LLM provided refined code — continuing to next round")

        logger.warning(" Max iterations reached. Final code may still contain violations.")
        return current_solution, False



    # def generate_java_from_solution(self, solution: str):
    #     # Run LLM to generate full Java code
    #     return self.llm.cogniCrypt_analysis(solution)

    # def run_pipeline(self, solution: str):
    #     llm_output = solution

    #     rules_dir = r"JCA-CrySL-rules"
    #     report_path = r"GeneratedCode"
    #     scanner_jar = r"CCJar/HeadlessJavaScanner-4.2.1-jar-with-dependencies.jar"

    #     # Save LLM output to Main.java
    #     java_file_path = save_llm_output(llm_output, "Main.java")

    #     # Compile Java
    #     class_file_path = compile_java(java_file_path)

    #     # Convert to JAR
    #     jar_file_path = convert_to_jar(class_file_path)

    #     # Run analysis
    #     run_cognicrypt(
    #         scanner_jar_path=scanner_jar,
    #         app_jar_path=jar_file_path,
    #         rules_dir=rules_dir,
    #         report_path=report_path,
    #         report_format="SARIF"
    #     )
    
def save_llm_output(code_str: str, filepath: str) -> str:
    with open(filepath, "w") as f:
        f.write(code_str)
    return filepath

def compile_java(filepath: str) -> str:
    compile_result = subprocess.run(["javac", filepath], capture_output=True, text=True)
    
    if compile_result.returncode != 0:
        raise Exception(f"Compilation failed:\n{compile_result.stderr}")

    class_file = filepath.replace(".java", ".class")
    if not os.path.exists(class_file):
        raise FileNotFoundError(f"Expected .class file not found: {class_file}")

    return class_file

def convert_to_jar(java_class_path: str) -> str:
    jar_file_name = java_class_path.replace(".class", ".jar")
    class_dir = os.path.dirname(java_class_path)
    class_file = os.path.basename(java_class_path)

    if not os.path.exists(java_class_path):
        raise FileNotFoundError(f"Class file does not exist: {java_class_path}")

    java_version = subprocess.run(["java", "--version"], text=True, capture_output=True)
    print("JAVA VERSION:", java_version.stdout.strip())

    original_cwd = os.getcwd()
    os.chdir(class_dir or ".")

    jar_result = subprocess.run(
        ["jar", "cf", os.path.basename(jar_file_name), class_file],
        capture_output=True, text=True
    )

    os.chdir(original_cwd)

    if jar_result.returncode != 0:
        raise Exception(f"JAR creation failed:\n{jar_result.stderr}")

    return os.path.join(class_dir, os.path.basename(jar_file_name))


def run_cognicrypt(scanner_jar_path, app_jar_path, rules_dir, report_path, report_format="SARIF"):
    cmd = [
        "java", "-jar", scanner_jar_path,
        "--rulesDir", rules_dir,
        "--appPath", app_jar_path,
        "--reportPath", report_path,
        "--reportFormat", report_format
    ]
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        logger.info("Analysis completed successfully.")
        logger.info(result.stdout)
    except subprocess.CalledProcessError as e:
        logger.info("Error during analysis:")
        logger.info(e.stderr)
