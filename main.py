from flask import Flask, request, jsonify
from flask_cors import CORS
from aifix import ai_fix
from logger_config import get_logger

logger = get_logger(__name__)

app = Flask(__name__)
CORS(app)
@app.route('/aifix', methods=['POST'])
def aifix():
    logger.info("Post API function to start the AI Fix analysis")
    try:
        request_data = request.get_json()
        # json_data = request_data["json_file"]
        code = request_data.get("code")
        rule = request_data.get("rule")
        message = request_data.get("msg")
        llm_model = request_data.get("llm_model", "openai")
        iterations = request_data.get("iterations", 3)
        logger.info("Fetch the vulnerable code snippet, CrySL rule violated, error type, selected LLM model and "
                    "number of iterations")

        if not code:
            logger.error("Error: Missing code snippet")
            return jsonify({"error": "Missing code snippet"}), 400

        logger.info("Data fetched, starting the analysis")
        result = ai_fix(code, rule, message, llm_model.lower(), iterations)

        return jsonify(result)

    except Exception as e:
        logger.error(f"Error : {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    logger.info("Starting the API")
    app.run(host='0.0.0.0', port=8000)
