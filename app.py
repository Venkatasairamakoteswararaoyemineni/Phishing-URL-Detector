from flask import Flask, render_template, request
import sqlite3
from detector import analyze_url
from datetime import datetime
import os

app = Flask(__name__)

DB_NAME = "phishing.db"

# -------------------------
# DATABASE SETUP
# -------------------------

def initialize_database():

    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT,
        result TEXT,
        score INTEGER,
        timestamp TEXT
    )
    """)

    conn.commit()
    conn.close()

# -------------------------
# SAVE SCAN
# -------------------------

def save_scan(url, result, score):

    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO scans(url, result, score, timestamp)
    VALUES (?, ?, ?, ?)
    """, (
        url,
        result,
        score,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()

# -------------------------
# DASHBOARD
# -------------------------

@app.route("/", methods=["GET", "POST"])
def dashboard():

    detection_result = None
    threat_score = None

    if request.method == "POST":

        url = request.form["url"]

        detection_result, threat_score = analyze_url(url)

        save_scan(url, detection_result, threat_score)

    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()

    cursor.execute("""
    SELECT * FROM scans
    ORDER BY id DESC
    LIMIT 20
    """)

    logs = cursor.fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        result=detection_result,
        score=threat_score,
        logs=logs
    )

# -------------------------
# MAIN
# -------------------------

if __name__ == "__main__":

    initialize_database()

    app.run(debug=True)