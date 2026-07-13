"""
app.py
Flask web app for the offline link-risk scanner.

Run:
    pip install flask
    python app.py
Then open http://127.0.0.1:5000
"""

from flask import Flask, render_template, request, jsonify
from analyzer import analyze_url

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Enter a URL to scan."}), 400
    if len(url) > 2000:
        return jsonify({"error": "URL is too long to scan."}), 400

    result = analyze_url(url)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
