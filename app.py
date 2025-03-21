from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
import sqlite3
import requests
import hashlib

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishing_urls.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define the database model


class PhishingURL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)


# Create database tables
with app.app_context():
    db.create_all()


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url")
        if url:
            new_entry = PhishingURL(url=url)
            db.session.add(new_entry)
            db.session.commit()
    phishing_urls = PhishingURL.query.all()

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
