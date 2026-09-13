# Secure Login System

A secure web authentication system built with Python, Flask, Bcrypt, and SQLite for the Thiranex B.Tech IT cybersecurity project track.

---

## Security Features

- **Bcrypt Password Hashing:** User passwords are never stored in plain text; salted Bcrypt hashes are generated before DB persistence.
- **SQL Injection Prevention:** All database operations utilize parameterized queries (`?` placeholders) to prevent SQLi vectors.
- **Session State Management:** Protected routes are guarded by cryptographic cookie-backed user sessions (`flask.session`).
- **Input Sanitization & Authentication:** Enforces input presence and handles duplicate account registrations securely.

---

## Installation & Setup

1. **Install required packages:**
   ```bash
   py -m pip install flask flask-bcrypt