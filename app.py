import os
import sqlite3
import re
from flask import Flask, render_template_string, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "default_fallback_secret_key")
bcrypt = Bcrypt(app)

DB_NAME = "users.db"

def init_db():
    """Parameterized database schema creation."""
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')
        conn.commit()

init_db()

def validate_input(username, password):
    """Input Validation & Sanitization based on security standards."""
    if not username or not password:
        return False, "Username and password cannot be empty."
    if len(username) < 3 or len(username) > 30:
        return False, "Username must be between 3 and 30 characters."
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        return False, "Username can only contain letters, numbers, and underscores."
    return True, ""

LOGIN_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure Login System</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f7f6; margin: 0; padding: 40px; display: flex; justify-content: center; }
        .card { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 340px; }
        h2 { text-align: center; color: #333; }
        input[type="text"], input[type="password"] { width: 100%; padding: 10px; margin: 8px 0; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
        button { width: 100%; background: #007bff; color: white; border: none; padding: 10px; border-radius: 4px; cursor: pointer; font-weight: bold; margin-top: 10px; }
        button:hover { background: #0056b3; }
        .flash { color: red; font-size: 14px; margin-bottom: 10px; text-align: center; }
        .toggle { text-align: center; margin-top: 15px; font-size: 13px; }
    </style>
</head>
<body>
    <div class="card">
        <h2>{{ title }}</h2>
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="flash">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <form method="POST" action="{{ action }}">
            <label>Username</label>
            <input type="text" name="username" required autocomplete="off">
            <label>Password</label>
            <input type="password" name="password" required>
            <button type="submit">{{ title }}</button>
        </form>
        <div class="toggle">
            {% if title == "Login" %}
                Don't have an account? <a href="/register">Register here</a>
            {% else %}
                Already have an account? <a href="/login">Login here</a>
            {% endif %}
        </div>
    </div>
</body>
</html>
'''

DASHBOARD_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #eef2f5; padding: 50px; text-align: center; }
        .container { background: white; padding: 40px; display: inline-block; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); }
        .btn-logout { background: #dc3545; color: white; text-decoration: none; padding: 10px 20px; border-radius: 4px; font-weight: bold; }
        .btn-logout:hover { background: #bd2130; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome, {{ username }}!</h1>
        <p>Authenticated using Bcrypt hashing, parameterized queries, and environment secrets.</p>
        <br><br>
        <a href="/logout" class="btn-logout">Logout</a>
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        is_valid, msg = validate_input(username, password)
        if not is_valid:
            flash(msg)
            return render_template_string(LOGIN_HTML, title="Register", action="/register")

        # Bcrypt Hashing with Salt Rounds
        pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            # Parameterized Query prevents SQL Injection
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, pw_hash))
                conn.commit()
            flash("Registration successful! Please login.")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username already exists.")

    return render_template_string(LOGIN_HTML, title="Register", action="/register")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        # Parameterized Query prevents SQL Injection
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user[0], password):
            session['user'] = username
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password.")

    return render_template_string(LOGIN_HTML, title="Login", action="/login")

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template_string(DASHBOARD_HTML, username=session['user'])

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    app.run(debug=True, port=port)