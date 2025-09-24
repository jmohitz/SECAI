from flask import Flask, request, jsonify
from flask_cors import CORS
from aifix import ai_fix
from logger_config import get_logger
import app_db

app_db.init_db()
logger = get_logger(__name__)

app = Flask(__name__)
CORS(app)

@app.route('/aifix', methods=['POST'])
def aifix():
    logger.info("Post API function to start the AI Fix analysis")
    try:
        request_data = request.get_json()
        code = request_data.get("code")
        rule = request_data.get("rule")
        message = request_data.get("msg")
        llm_model = request_data.get("llm_model", "openai")
        iterations_cc = request_data.get("iterations", 3)

        logger.info("Fetched the vulnerable code snippet, CrySL rule violated, error type, selected LLM model and number of iterations")

        if not code:
            logger.error("Error: Missing code snippet")
            return jsonify({"error": "Missing code snippet"}), 400

        input_data = {
            "code": code,
            "rule": rule,
            "msg": message,
            "llm_model": llm_model,
            "iterations": iterations_cc
        }

        # DB Cache Lookup
        cached = app_db.get_record_by_input(input_data)
        if cached is not None:
            logger.info("Returning cached LLM result from DB.")
            return jsonify(cached["output"])

        logger.info("Data not found in cache, starting the analysis")
        result = ai_fix(code, rule, message, llm_model.lower(), iterations_cc)

         # Normalize error dicts returned by ai_fix (non-exception path)
        if isinstance(result, dict) and "error" in result:
            err = str(result["error"])
            logger.error(f"ai_fix returned error: {err}")
            if "COMPILATION_ERROR" in err or "Compilation failed" in err:
                return jsonify({"error": "Error compiling code. Please select a different model."}), 400
            return jsonify({"error": "An error occurred during analysis. Please try again."}), 500

        # Only save to DB if result is not an error
        app_db.save_analysis_record(input_data, result)
        return jsonify(result)

    except Exception as e:
        msg = str(e)
        logger.error(f"Error: {msg}")
        if "COMPILATION_ERROR" in msg or "Compilation failed" in msg:
            return jsonify({"error": "Error compiling code. Please select a different model."}), 400
        return jsonify({"error": "An error occurred during analysis. Please try again."}), 500

if __name__ == '__main__':
    logger.info("Starting the API")
    app.run(host='0.0.0.0', port=8000)
