from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
from utils import check_url_virustotal
import hashlib
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishing_urls.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define database model


class PhishingURL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)


# Create database tables
with app.app_context():
    db.create_all()

# Known malicious file hashes (example)
malicious_hashes = {
    "5d41402abc4b2a76b9719d911017c592",  # Example MD5 hash
    "7d793037a0760186574b0282f2f435e7"
}

# Function to check if URL is phishing


def check_url(url):
    phishing_keywords = ["login", "verify", "secure", "bank", "update"]
    if any(keyword in url.lower() for keyword in phishing_keywords):
        return "⚠️ Suspicious URL detected!"
    if not url.startswith("https"):
        return "⚠️ Warning: Website is not using HTTPS."
    return "✅ URL seems safe."

# Function to check file hash


def check_file_hash(file):
    file_hash = hashlib.sha256(file.read()).hexdigest()
    if file_hash in malicious_hashes:
        return "⚠️ Warning: Malicious file detected!"
    return "✅ File is safe."


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    if request.method == "POST":
        url = request.form.get("url")
        if url:
            result = check_url(url)
            new_entry = PhishingURL(url=url)
            db.session.add(new_entry)
            db.session.commit()

    phishing_urls = PhishingURL.query.all()
    return render_template("index.html", result=result, urls=phishing_urls)


@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return "⚠️ No file uploaded."

    file = request.files["file"]
    if file.filename == "":
        return "⚠️ No file selected."

    result = check_file_hash(file)
    return result


if __name__ == "__main__":
    app.run(debug=True)
