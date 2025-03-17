import json
from flask import Flask, request, jsonify
from rag_faiss import process_analysis
import logging

open('aifix.log', 'w').close()
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
logging.basicConfig(filename='aifix.log', level=logging.INFO,  format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
@app.route('/aifix', methods=['POST'])
def aifix():
    logger.info("Post API function to start the AI Fix analysis")
    try:
        json_file = request.files.get("json_file")
        code = request.form.get("code")
        logger.info("Fetch the Crypto Analysis JSON report as well as the vulnerable code snippet")

        if not json_file or not code:
            return jsonify({"error": "Missing json_file or code"}), 400

        json_data = json.load(json_file)
        logger.info("JSON File and code fetched, calling the process analysis function")
        result = process_analysis(json_data, code)

        return jsonify(result)

    except Exception as e:
        logger.error(f"Error : {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    logger.info("Starting the API")
    app.run(host='0.0.0.0', port=8000)
