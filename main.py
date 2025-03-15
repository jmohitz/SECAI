import json
from flask import Flask, request, jsonify
from rag_faiss import process_analysis

app = Flask(__name__)

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        json_file = request.files.get("json_file")
        code = request.form.get("code")

        if not json_file or not code:
            return jsonify({"error": "Missing json_file or code"}), 400

        json_data = json.load(json_file)

        # Call the analysis function from rag_faiss.py
        result = process_analysis(json_data, code)

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)