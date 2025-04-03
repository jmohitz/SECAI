from flask import Flask, request, jsonify
from flask_cors import CORS
from rag_faiss import process_analysis
import logging

open('aifix.log', 'w').close()
logging.basicConfig(filename='aifix.log', level=logging.INFO,  format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)
@app.route('/aifix', methods=['POST'])
def aifix():
    logger.info("Post API function to start the AI Fix analysis")
    try:
        request_data = request.get_json()
        json_data = request_data["json_file"]
        code = request_data["code"]
        rule = request_data["rule"]
        message = request_data["msg"]
        logger.info("Fetch the Crypto Analysis JSON report, vulnerable code snippet, CrySL rule violated and error type")

        if not json_data or not code:
            logger.error("Error: Missing json_file or code")
            return jsonify({"error": "Missing json_file or code"}), 400

        logger.info("JSON File and code fetched, calling the process analysis function")
        result = process_analysis(json_data, code, rule, message)

        return jsonify(result)

    except Exception as e:
        logger.error(f"Error : {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    logger.info("Starting the API")
    app.run(host='0.0.0.0', port=8000)
