from flask import Flask, render_template, request
import sqlite3
import requests
import hashlib

app = Flask(__name__)

# Function to check if URL is phishing


def check_url(url):
    phishing_keywords = ["login", "verify", "secure", "bank", "update"]
    if any(keyword in url.lower() for keyword in phishing_keywords):
        return "Suspicious URL detected!"
    if not url.startswith("https"):
        return "Warning: Website is not using HTTPS."
    return "URL seems safe."

# Function to check file hash


def check_file_hash(file_path):
    with open(file_path, "rb") as f:
        file_data = f.read()
        file_hash = hashlib.sha256(file_data).hexdigest()
    return file_hash


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    if request.method == "POST":
        url = request.form.get("url")
        if url:
            result = check_url(url)
    return render_template("index.html", result=result)


if __name__ == "__main__":
    app.run(debug=True)
