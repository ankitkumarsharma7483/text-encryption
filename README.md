# Cipher Desk (TEXT_ENCRYPTION_SYSTEM)

Flask app to encrypt and decrypt text with AES-256-GCM, DES-CBC (educational) and hybrid RSA-OAEP.

## Run
```bash
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
# edit .env and set SECRET_KEY and MASTER_KEY (python -c "import secrets; print(secrets.token_hex(32))")
python app.py            # http://127.0.0.1:5000
```

## How it works
- **AES-256-GCM**: random 96-bit nonce per message; the auth tag detects tampering.
- **DES-CBC**: 56-bit effective key, broken. Included for comparison only.
- **RSA**: 2048-bit OAEP wraps a random AES-256 session key (hybrid), so long text works.
- **Key storage**: all secret/private keys are encrypted with `MASTER_KEY` (AES-GCM) before hitting `database.db`.
  Changing `MASTER_KEY` makes existing keys unreadable, so back it up.
- **Auth**: scrypt password hashes, Flask-Login sessions, CSRF protection on every form, security headers.
- **History** stores metadata and ciphertext, never the original plaintext.

## Before production
Serve behind HTTPS (set `SESSION_COOKIE_SECURE = True`), use a real WSGI server (gunicorn/waitress),
add login rate limiting (Flask-Limiter), and keep `MASTER_KEY` in a secrets manager.


## HOW TO RUN THIS PROJECT

1. Unzip and open a terminal in the folder
unzip TEXT_ENCRYPTION_SYSTEM.zip
cd TEXT_ENCRYPTION_SYSTEM

2. Check you have Python 3.9 or newer
python --version

3. Create and activate a virtual environment

python -m venv venv
venv\Scripts\activate

4. Install the dependencies
pip install -r requirements.txt


5. Set your secrets in .env

python -c "import secrets; print(secrets.token_hex(32))"

7. See what's in the current folder
dir

8. 
cd TEXT_ENCRYPTION_SYSTEM
dir

9. 
pip install -r requirements.txt

10. 
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

11. 
python -c "import secrets; print(secrets.token_hex(32))"

12. 
python app.py






