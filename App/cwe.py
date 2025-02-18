import json
import os

def clean_text(text):
    """Remove semicolons, dots, and colons from text"""
    return text.translate(str.maketrans('', '', ';.:')) if text else text

def process_cve_json(input_dir, output_dir):
    """Process CVE JSON files and save as individual text files"""
    os.makedirs(output_dir, exist_ok=True)
    
    for root, _, files in os.walk(input_dir):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8') as f:
                    try:
                        data = json.load(f)
                        cve_id = clean_text(data['cveMetadata']['cveId'])
                        
                        # Extract English description
                        descriptions = data['containers']['cna']['descriptions']
                        description = next((d['value'] for d in descriptions if d['lang'] == 'en'), '')
                        description = clean_text(description)
                        
                        # Collect unique URLs
                        urls = set()
                        for ref in data['containers']['cna'].get('references', []):
                            urls.add(clean_text(ref['url']))
                        for adp in data['containers'].get('adp', []):
                            for ref in adp.get('references', []):
                                urls.add(clean_text(ref['url']))
                        
                        # Add encoding='utf-8' here
                        output_path = os.path.join(output_dir, f"{cve_id}.txt")
                        with open(output_path, 'w', encoding='utf-8') as outfile:
                            outfile.write(f"CVE-ID: {cve_id}\n")
                            outfile.write(f"Description: {description}\n")
                            outfile.write("References:\n" + "\n".join(urls))
                            
                    except Exception as e:
                        print(f"Error processing {file_path}: {str(e)}")

process_cve_json("C:/Users/jmohi/Downloads/699.csv/699.csv", "cve_output")