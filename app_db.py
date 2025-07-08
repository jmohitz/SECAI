import sqlite3
import json
from datetime import datetime

DB_FILE = "analysis_results.db"

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS analysis_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT,
            rule TEXT,
            msg TEXT,
            llm_model TEXT,
            iterations INTEGER,
            output_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(code, rule, msg, llm_model, iterations)
        );
        """)
        conn.commit()


def save_analysis_record(input_data, output_data):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR IGNORE INTO analysis_records
            (code, rule, msg, llm_model, iterations, output_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            input_data.get("code"),
            input_data.get("rule"),
            input_data.get("msg"),
            input_data.get("llm_model"),
            input_data.get("iterations"),
            json.dumps(output_data),
            datetime.now()
        ))
        conn.commit()


def get_all_records():
    """Return all saved analysis records as a list of dicts."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, code, rule, msg, llm_model, iterations, output_json, created_at FROM analysis_records ORDER BY id DESC")
        rows = cursor.fetchall()
        records = []
        for row in rows:
            record = {
                "id": row[0],
                "code": row[1],
                "rule": row[2],
                "msg": row[3],
                "llm_model": row[4],
                "iterations": row[5],
                "output": json.loads(row[6]),
                "created_at": row[7]
            }
            records.append(record)
        return records
    
def get_record_by_input(input_data):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, code, rule, msg, llm_model, iterations, output_json, created_at
            FROM analysis_records
            WHERE code=? AND rule=? AND msg=? AND llm_model=? AND iterations=?
            ORDER BY created_at DESC LIMIT 1
        """, (
            input_data.get("code"),
            input_data.get("rule"),
            input_data.get("msg"),
            input_data.get("llm_model"),
            input_data.get("iterations")
        ))
        row = cursor.fetchone()
        if not row:
            return None
        try:
            output_parsed = json.loads(row[6])
        except Exception as e:
            output_parsed = {"error": str(e), "raw": row[6]}
        return {
            "id": row[0],
            "code": row[1],
            "rule": row[2],
            "msg": row[3],
            "llm_model": row[4],
            "iterations": row[5],
            "output": output_parsed,
            "created_at": row[7]
        }

    
    

# # Only for manual testing (optional)
# if __name__ == '__main__':
#     init_db()
#     print("Database initialized.")

#     # Test saving a record
#     input_data = {
#         "code": "example code",
#         "rule": "example rule",
#         "msg": "example msg",
#         "llm_model": "gemini",
#         "iterations": 1
#     }
#     output_data = {
#         "Explanation": "example explanation",
#         "Final_Secure_Code_Snippet": "fixed code"
#     }
#     save_analysis_record(input_data, output_data)
#     print("All records:\n", get_all_records())
