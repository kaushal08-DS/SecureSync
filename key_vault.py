from flask import Flask, request, jsonify
import sqlite3

SECRET_TOKEN = "ghostvault_super_secret_2026"

app = Flask(__name__)

# Create database table
def init_db():
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS file_keys (
            file_id TEXT PRIMARY KEY,
            encryption_key TEXT
        )
    """)

    conn.commit()
    conn.close()

init_db()


# Store key
@app.route("/store_key", methods=["POST"])
def store_key():

    auth_token = request.headers.get("Authorization")

    if auth_token != f"Bearer {SECRET_TOKEN}":
        return jsonify({
            "error": "Unauthorized access"
        }), 401

    data = request.json

    file_id = data["file_id"]
    encryption_key = data["encryption_key"]

    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()

    cursor.execute("""
        INSERT OR REPLACE INTO file_keys
        VALUES (?, ?)
    """, (file_id, encryption_key))

    conn.commit()
    conn.close()

    return jsonify({
        "message": "Key stored successfully"
    })


# Retrieve key
@app.route("/get_key/<file_id>", methods=["GET"])
def get_key(file_id):

    auth_token = request.headers.get("Authorization")

    if auth_token != f"Bearer {SECRET_TOKEN}":
        return jsonify({
            "error": "Unauthorized access"
        }), 401

    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT encryption_key
        FROM file_keys
        WHERE file_id=?
    """, (file_id,))

    result = cursor.fetchone()

    conn.close()

    if result:
        return jsonify({
            "encryption_key": result[0]
        })

    return jsonify({
        "error": "Key not found"
    }), 404


if __name__ == "__main__":
    app.run(port=5001, debug=True)