import argparse
import json
from aifix import ai_fix
from logger_config import get_logger

logger = get_logger(__name__)

def main():
    parser = argparse.ArgumentParser(description="AI Fix Analysis Tool")
    parser.add_argument("--json_file", type=str, required=True, help="Path to the JSON file containing the analysis report")
    parser.add_argument("--code", type=str, required=True, help="The code snippet to analyze")
    parser.add_argument("--rule", type=str, required=True, help="The CrySL rule that was violated")
    parser.add_argument("--msg", type=str, required=True, help="The error type message")
    args = parser.parse_args()

    try:
        # Load JSON data from the provided file path
        with open(args.json_file, "r", encoding="utf-8") as f:
            json_data = json.load(f)

        # Run the AI Fix analysis
        result = ai_fix(json_data, args.code, args.rule, args.msg)
        
        # Print the result as a JSON string to standard output
        print(json.dumps(result))
    except Exception as e:
        logger.error("Error: " + str(e))
        # Print error details in JSON format and exit with a non-zero code
        print(json.dumps({"error": str(e)}))
        exit(1)

if __name__ == '__main__':
    main()
