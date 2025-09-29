from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import tldextract
import pandas as pd
import re
import sqlite3
import requests
import os
import imaplib, email
from email.header import decode_header
from datetime import datetime
from model.feature_extractor import extract_url_features
from dotenv import load_dotenv
import json
import time


DB_PATH = "data/app.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            domain TEXT,
            verdict TEXT,
            confidence_pct INTEGER,
            recommended_action TEXT,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

# Call at startup
init_db()


# ===============================
# Load .env
# ===============================
load_dotenv()
IMAP_HOST = os.getenv("IMAP_HOST", "imap.ethereal.email")
IMAP_PORT = int(os.getenv("IMAP_PORT", 993))
IMAP_USER = os.getenv("IMAP_USER", "vincenza.legros@ethereal.email")
IMAP_PASS = os.getenv("IMAP_PASS", "gtxbgVZq21qwycy6Dj")
VT_API_KEY = os.getenv("VT_API_KEY", "6b53b66dfd3797e9c926d63b069c7ad81f48cbb91454a0f2cca5fdf783dd3427")

# ===============================
# Flask setup
# ===============================
app = Flask(__name__)
CORS(app)

MODEL_PATH = "model/url_model.pkl"
COLS_PATH = "model/model_columns.pkl"
DB_PATH = "data/app.db"

# ===============================
# Load AI model
# ===============================
model = joblib.load(MODEL_PATH)
expected_columns = joblib.load(COLS_PATH)

# ===============================
# Database setup (adds vt_cache + retrain_data)
# ===============================
os.makedirs("data", exist_ok=True)
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
c = conn.cursor()

# history table (unchanged)
c.execute("""
CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT,
    domain TEXT,
    verdict TEXT,
    confidence_pct INTEGER,
    recommended_action TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

# vt_cache: cache the VirusTotal response summary to avoid repeated VT calls
c.execute("""
CREATE TABLE IF NOT EXISTS vt_cache (
    url TEXT PRIMARY KEY,
    vt_verdict TEXT,
    vt_stats_json TEXT,
    checked_at DATETIME
)
""")

# retrain_data: store final label so future checks skip VT and use DB label (preserve VT quotas)
c.execute("""
CREATE TABLE IF NOT EXISTS retrain_data (
    url TEXT PRIMARY KEY,
    label TEXT,
    added_at DATETIME
)
""")

conn.commit()

# ===============================
# Helper: VirusTotal checker (returns "Phishing"/"Suspicious"/"Legitimate"/None)
# ===============================
def call_virustotal(url):
    """Call VirusTotal once and return (vt_verdict, raw_stats_dict) or (None, None) on failure."""
    if not VT_API_KEY:
        return None, None
    try:
        headers = {"x-apikey": VT_API_KEY}
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=25
        )
        if response.status_code != 200:
            # sometimes VT returns 200 for submit, 200+ for analysis fetch - continue gracefully
            return None, None

        result = response.json()
        analysis_id = result["data"]["id"]
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        # Wait briefly and fetch analysis (VT can be eventual) — try a couple times
        for _ in range(3):
            res = requests.get(analysis_url, headers=headers, timeout=25)
            if res.status_code == 200:
                attrs = res.json().get("data", {}).get("attributes", {})
                stats = attrs.get("stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                # Interpret: even 1 malicious -> Phishing
                if malicious >= 1:
                    return "Phishing", stats
                elif suspicious >= 1:
                    return "Suspicious", stats
                else:
                    return "Legitimate", stats
            # if not ready, sleep a bit and retry
            time.sleep(1)
        return None, None
    except Exception as e:
        print("⚠️ VirusTotal call error:", e)
        return None, None

# ===============================
# Routes
# ===============================
@app.route("/")
def home():
    return "✅ Link Safety Checker API is running!"


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = data.get("url")
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    url = url.strip()

    # 1) If retrain_data has this URL, use it directly (skip VT)
    c.execute("SELECT label, added_at FROM retrain_data WHERE url = ?", (url,))
    row = c.fetchone()
    if row:
        stored_label = row[0]
        if stored_label.lower() == "phishing":
            verdict, recommendation, confidence = "Phishing", "Do not click", 95
        elif stored_label.lower() == "suspicious":
            verdict, recommendation, confidence = "Suspicious", "Proceed with caution", 80
        else:
            verdict, recommendation, confidence = "Legitimate", "Safe to open", 90

        domain_info = tldextract.extract(url)
        domain = f"{domain_info.domain}.{domain_info.suffix}"
        c.execute("""
            INSERT INTO history (url, domain, verdict, confidence_pct, recommended_action, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (url, domain, verdict, confidence, recommendation, datetime.now()))
        conn.commit()
        return jsonify({
            "url": url,
            "domain": domain,
            "verdict": verdict,
            "confidence_pct": confidence,
            "recommended_action": recommendation
        })

    # 2) Check vt_cache
    c.execute("SELECT vt_verdict, vt_stats_json, checked_at FROM vt_cache WHERE url = ?", (url,))
    vt_row = c.fetchone()
    vt_verdict = None
    vt_stats = None
    if vt_row:
        vt_verdict = vt_row[0]
        try:
            vt_stats = json.loads(vt_row[1]) if vt_row[1] else None
        except:
            vt_stats = None

    # 3) If no vt_cache, call VirusTotal
    if not vt_verdict:
        vt_verdict, vt_stats = call_virustotal(url)
        if vt_verdict is not None:
            try:
                c.execute("""
                    INSERT OR REPLACE INTO vt_cache (url, vt_verdict, vt_stats_json, checked_at)
                    VALUES (?, ?, ?, ?)
                """, (url, vt_verdict, json.dumps(vt_stats or {}), datetime.now()))
                conn.commit()
            except Exception as e:
                print("⚠️ Failed to write vt_cache:", e)

    # 4) Dataset check (master_urls.csv override)
    dataset_verdict = None
    try:
        df_master = pd.read_csv("data/master_urls.csv")
        match = df_master[df_master["url"].str.lower() == url.lower()]
        if not match.empty:
            label = str(match.iloc[0]["label"]).lower()
            if label in ["phishing", "1"]:
                dataset_verdict = "Phishing"
            elif label in ["suspicious"]:
                dataset_verdict = "Suspicious"
            else:
                dataset_verdict = "Legitimate"
    except Exception as e:
        print("⚠️ Could not check master dataset:", e)

    # 5) Compute AI model prediction
    features = extract_url_features(url)
    X = pd.DataFrame([features])
    X = pd.get_dummies(X, columns=["suffix"])
    X = X.reindex(columns=expected_columns, fill_value=0)

    try:
        prediction = model.predict(X)[0]
        probabilities = model.predict_proba(X)[0]
        ai_confidence = int(max(probabilities) * 100)
    except Exception as e:
        print("⚠️ AI prediction error:", e)
        prediction = 0
        ai_confidence = 50

    # 6) Combine decisions (priority: Dataset > VirusTotal > AI)
    if vt_verdict == "Phishing":
    verdict, recommendation, confidence = "Phishing", "Do not click", 95
elif vt_verdict == "Legitimate":
    verdict, recommendation, confidence = "Legitimate", "Safe to open", 95
elif prediction == 1 and ai_confidence >= 70:
    verdict, recommendation, confidence = "Suspicious", "Proceed with caution", ai_confidence
else:
    verdict, recommendation, confidence = "Legitimate", "Safe to open", max(ai_confidence, 90)


    # 7) Save to retrain_data
    try:
        c.execute("""
            INSERT OR REPLACE INTO retrain_data (url, label, added_at)
            VALUES (?, ?, ?)
        """, (url, verdict, datetime.now()))
        conn.commit()
    except Exception as e:
        print("⚠️ Failed to write retrain_data:", e)

    # 8) Save to history
    domain_info = tldextract.extract(url)
    domain = f"{domain_info.domain}.{domain_info.suffix}"

    c.execute("""
        INSERT INTO history (url, domain, verdict, confidence_pct, recommended_action, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (url, domain, verdict, confidence, recommendation, datetime.now()))
    conn.commit()

    return jsonify({
        "url": url,
        "domain": domain,
        "verdict": verdict,
        "confidence_pct": confidence,
        "recommended_action": recommendation
    })


@app.route("/history", methods=["GET"])
def get_history():
    c.execute("SELECT url, domain, verdict, confidence_pct, recommended_action, timestamp FROM history ORDER BY id DESC LIMIT 10")
    rows = c.fetchall()
    history = []
    for row in rows:
        history.append({
            "url": row[0],
            "domain": row[1],
            "verdict": row[2],
            "confidence_pct": row[3],
            "recommended_action": row[4],
            "timestamp": row[5]
        })
    return jsonify(history)

# 🔹 Add this new route here
@app.route('/stats', methods=['GET'])
def get_stats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT verdict, COUNT(*) FROM history GROUP BY verdict")
    rows = c.fetchall()
    conn.close()

    stats = {"Legitimate": 0, "Phishing": 0, "Suspicious": 0}
    for verdict, count in rows:
        stats[verdict] = count
    return jsonify(stats)


@app.route("/inbox", methods=["GET"])
def get_inbox():
    try:
        mail = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
        mail.login(IMAP_USER, IMAP_PASS)
        mail.select("inbox")

        status, messages = mail.search(None, "ALL")
        email_ids = messages[0].split()[-5:]  # last 5 emails

        inbox_data = []
        for eid in reversed(email_ids):
            res, msg_data = mail.fetch(eid, "(RFC822)")
            msg = email.message_from_bytes(msg_data[0][1])

            subject, encoding = decode_header(msg["Subject"])[0]
            if isinstance(subject, bytes):
                subject = subject.decode(encoding or "utf-8", errors="ignore")

            from_ = msg.get("From")
            body = ""
            links = []

            # Extract text + HTML (look for hrefs in HTML)
            if msg.is_multipart():
                for part in msg.walk():
                    ctype = part.get_content_type()
                    if ctype == "text/plain":
                        try:
                            txt = part.get_payload(decode=True).decode(errors="ignore")
                            body += txt
                            links.extend(re.findall(r"https?://[^\s\"'>]+", txt))
                        except:
                            continue
                    elif ctype == "text/html":
                        try:
                            html = part.get_payload(decode=True).decode(errors="ignore")
                            links.extend(re.findall(r'href=[\'"]?([^\'" >]+)', html))
                            links.extend(re.findall(r"https?://[^\s\"'>]+", html))
                        except:
                            continue
            else:
                try:
                    body = msg.get_payload(decode=True).decode(errors="ignore")
                    links.extend(re.findall(r"https?://[^\s\"'>]+", body))
                except:
                    pass

            inbox_data.append({
                "subject": subject,
                "from": from_,
                "links": list(dict.fromkeys(links))  # preserve order, unique
            })

        mail.logout()
        return jsonify(inbox_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ===============================
# Run
# ===============================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Render sets PORT automatically
    print(f"🚀 Starting on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)