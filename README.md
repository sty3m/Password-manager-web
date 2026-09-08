# PyVault Web — A Secure, Self-Hostable Password Manager

A full-stack password manager (Flask + vanilla JS, no frontend framework required) built to demonstrate correct, practical use of modern cryptography and sound web application security design.

## Features

- AES-256-GCM authenticated encryption
- Unique random salt per user
- PBKDF2-HMAC-SHA256 with 600,000 iterations
- Server-side in-memory session key storage
- Cryptographically secure password generator
- Master-password rotation with vault re-encryption
- No username enumeration
- Automated test suite via GitHub Actions

## Run locally

```bash
python -m venv venv
# Windows: venv\Scripts\activate
# Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000.

For production, use HTTPS and a real WSGI server. This is an educational/portfolio project; review the threat-model limitations before using it for real secrets.

## Tests

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

## License

MIT — see `LICENSE`.
