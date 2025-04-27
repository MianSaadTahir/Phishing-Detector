from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import hashlib
from utils import check_url_virustotal, check_file_virustotal
from pawned_check import check_password_pawned  # ✅ Import Pawned Checker

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishing_urls.db'
app.config['SQLALCHEMY_BINDS'] = {
    'blocked_ips': 'sqlite:///blocked_ips.db',
    'pawned_data': 'sqlite:///pawned_data.db',
    'users': 'sqlite:///users.db'  # ✅ New DB for User Management
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'  # Needed for sessions

db = SQLAlchemy(app)

# ✅ Rate Limiting
app.config['RATELIMIT_STORAGE_URI'] = "memory://"  # Change to Redis in production
limiter = Limiter(get_remote_address)
limiter.init_app(app)

# ✅ Database Models
class PhishingURL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), unique=True, nullable=False)
    status = db.Column(db.String(20), nullable=False)
    detected_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class BlockedIP(db.Model):
    __bind_key__ = 'blocked_ips'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), unique=True, nullable=False)

class PawnedData(db.Model):
    __bind_key__ = 'pawned_data'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), unique=True, nullable=True)
    breaches_count = db.Column(db.Integer, default=0)

class User(db.Model):
    __bind_key__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# ✅ Helper Functions
def check_url(url):
    phishing_keywords = ["login", "verify", "secure", "bank", "update"]
    if any(keyword in url.lower() for keyword in phishing_keywords):
        return "⚠️ Phishing URL detected!"
    if not url.startswith("https"):
        return "⚠️ Warning: Website is not using HTTPS."
    return "✅ URL is safe."

malicious_hashes = {
    "5d41402abc4b2a76b9719d911017c592",
    "7d793037a0760186574b0282f2f435e7"
}

def check_file_hash(file):
    file_hash = hashlib.sha256(file.read()).hexdigest()
    if file_hash in malicious_hashes:
        return "⚠️ Warning: Malicious file detected!"
    return "✅ File is safe."

# ✅ Login Required Decorator
from functools import wraps
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ✅ Authentication Routes
@app.route("/sign_up", methods=["GET", "POST"])
def sign_up():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username and password:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            if not User.query.filter_by(username=username).first():
                new_user = User(username=username, password=hashed_password)
                db.session.add(new_user)
                db.session.commit()
                flash("✅ Account created successfully! Please log in.", "success")
                return redirect(url_for('login'))
            else:
                flash("⚠️ Username already exists.", "danger")
    return render_template("sign_up.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        user = User.query.filter_by(username=username, password=hashed_password).first()
        if user:
            session['user_id'] = user.id
            flash("✅ Logged in successfully!", "success")
            return redirect(url_for('home'))
        else:
            flash("⚠️ Invalid username or password.", "danger")
    return render_template("sign_in.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("✅ You have been logged out.", "success")
    return redirect(url_for('login'))

# ✅ Main Features
@app.route("/")
@login_required
def home():
    return render_template("index.html")

@app.route("/phishing_checker", methods=["GET", "POST"])
@login_required
@limiter.limit("5 per minute")
def phishing_checker():
    result, vt_result = None, None
    if request.method == "POST":
        url = request.form.get("url")
        if url:
            result = check_url(url)
            vt_result = check_url_virustotal(url)

            existing_entry = PhishingURL.query.filter_by(url=url).first()
            if not existing_entry:
                status = "Phishing" if "⚠️" in result else "Safe"
                new_entry = PhishingURL(url=url, status=status)
                db.session.add(new_entry)
                db.session.commit()
            else:
                flash("This URL is already in the database.", "info")

    return render_template("phishing_checker.html", result=result, vt_result=vt_result)

@app.route("/file_scan", methods=["GET", "POST"])
@login_required
@limiter.limit("5 per minute")
def file_scan():
    file_result = None
    if request.method == "POST":
        if "file" not in request.files:
            file_result = "⚠️ No file uploaded."
        else:
            file = request.files["file"]
            if file.filename == "":
                file_result = "⚠️ No file selected."
            else:
                file_result = check_file_virustotal(file)

    return render_template("file_scan.html", file_result=file_result)

@app.route("/pawned_checker", methods=["GET", "POST"])
@login_required
@limiter.limit("5 per minute")
def pawned_checker():
    password_result = None
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if email:
            if not PawnedData.query.filter_by(email=email).first():
                new_email = PawnedData(email=email)
                db.session.add(new_email)
                db.session.commit()
            return redirect(f"https://haveibeenpwned.com/account/{email}")

        if password:
            password_count, password_hash = check_password_pawned(password, return_hash=True)
            existing_password = PawnedData.query.filter_by(password_hash=password_hash).first()
            if not existing_password:
                new_password = PawnedData(password_hash=password_hash, breaches_count=password_count)
                db.session.add(new_password)
                db.session.commit()

            password_result = f"Password found {password_count} times in breaches" if password_count else "✅ Password is safe!"

    return render_template("pawned_checker.html", password_result=password_result)

@app.route("/ddos_test")
@login_required
@limiter.limit("5 per minute")
def ddos_test():
    return render_template("ddos_test.html")

@app.errorhandler(429)
def too_many_requests(e):
    ip = get_remote_address()
    if not BlockedIP.query.filter_by(ip_address=ip).first():
        db.session.add(BlockedIP(ip_address=ip))
        db.session.commit()
    return render_template("too_many_requests.html", ip=ip), 429

@app.route("/admin")
@login_required
def admin():
    return render_template("admin.html", blocked_ips=BlockedIP.query.all())

@app.route("/unblock/<ip>")
@login_required
def unblock(ip):
    blocked_ip = BlockedIP.query.filter_by(ip_address=ip).first()
    if blocked_ip:
        db.session.delete(blocked_ip)
        db.session.commit()
    return redirect(url_for("admin"))

# ✅ Start App
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
