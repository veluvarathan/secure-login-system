# Secure Login System

A secure web authentication system built with Python, Flask, Bcrypt, and SQLite, incorporating backend security best practices.

---

## Security Implementation Features

- **Input Validation & Sanitization:** Enforces length constraints, character rules, and presence checks for request payloads.
- **Bcrypt Password Hashing:** User credentials are secured using salted Bcrypt hashing before storage.
- **Environment Variable Isolation (`dotenv`):** Sensitive application secrets and ports are kept in `.env` and untracked in Git.
- **SQL Injection Prevention:** Uses parameterized SQL queries (`?` placeholders) for all database operations.
- **Session Management:** Handles user login states using secure cookie-backed sessions.

---

## Setup & Running

1. **Install Dependencies:**
   ```bash
   py -m pip install flask flask-bcrypt python-dotenv

2. **Bash**
   py app.py