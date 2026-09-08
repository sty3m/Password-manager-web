"""
app.py

Flask application factory + REST API routes for PyVault Web.
"""

import os
from flask import Flask, jsonify, request, session, g, render_template
from cryptography.exceptions import InvalidTag
from password_manager import crypto_utils, db, session_store, vault


def create_app(db_path: str = None) -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("PYVAULT_SECRET_KEY", os.urandom(32))
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["DB_PATH"] = db_path

    with app.app_context():
        db.init_db(db_path)

    def require_auth():
        token = session.get("token")
        s = session_store.get_session(token)
        if s is None:
            return None
        g.user_id = s["user_id"]
        g.username = s["username"]
        g.key = s["key"]
        return s

    def auth_required(view_func):
        from functools import wraps
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            if require_auth() is None:
                return jsonify({"error": "Not authenticated"}), 401
            return view_func(*args, **kwargs)
        return wrapper

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/register", methods=["POST"])
    def api_register():
        data = request.get_json(silent=True) or {}
        username = (data.get("username") or "").strip()
        master_password = data.get("master_password") or ""
        if len(username) < 3:
            return jsonify({"error": "Username must be at least 3 characters"}), 400
        if len(master_password) < 8:
            return jsonify({"error": "Master password must be at least 8 characters"}), 400
        try:
            vault.register_user(username, master_password, app.config["DB_PATH"])
        except vault.UsernameTaken as e:
            return jsonify({"error": str(e)}), 409
        return jsonify({"message": "Account created. You can now log in."}), 201

    @app.route("/api/login", methods=["POST"])
    def api_login():
        data = request.get_json(silent=True) or {}
        username = (data.get("username") or "").strip()
        master_password = data.get("master_password") or ""
        try:
            user_id, uname, key = vault.authenticate(username, master_password, app.config["DB_PATH"])
        except vault.InvalidCredentials as e:
            return jsonify({"error": str(e)}), 401
        token = session_store.create_session(user_id, uname, key)
        session["token"] = token
        session.permanent = False
        return jsonify({"message": "Logged in", "username": uname})

    @app.route("/api/logout", methods=["POST"])
    def api_logout():
        token = session.get("token")
        if token:
            session_store.destroy_session(token)
        session.clear()
        return jsonify({"message": "Logged out"})

    @app.route("/api/me", methods=["GET"])
    def api_me():
        s = require_auth()
        if s is None:
            return jsonify({"authenticated": False})
        return jsonify({"authenticated": True, "username": s["username"]})

    @app.route("/api/entries", methods=["GET"])
    @auth_required
    def api_list_entries():
        services = vault.list_services(g.user_id, g.key, app.config["DB_PATH"])
        return jsonify({"services": services})

    @app.route("/api/entries", methods=["POST"])
    @auth_required
    def api_add_entry():
        data = request.get_json(silent=True) or {}
        service = (data.get("service") or "").strip()
        username = data.get("username") or ""
        password = data.get("password") or ""
        notes = data.get("notes") or ""
        if not service:
            return jsonify({"error": "Service name is required"}), 400
        if not password:
            return jsonify({"error": "Password is required"}), 400
        vault.add_entry(g.user_id, g.key, service, username, password, notes, app.config["DB_PATH"])
        return jsonify({"message": f"Saved entry for '{service}'"}), 201

    @app.route("/api/entries/<path:service>", methods=["GET"])
    @auth_required
    def api_get_entry(service):
        entry = vault.get_entry(g.user_id, g.key, service, app.config["DB_PATH"])
        if entry is None:
            return jsonify({"error": f"No entry found for '{service}'"}), 404
        return jsonify({"service": service, **entry})

    @app.route("/api/entries/<path:service>", methods=["DELETE"])
    @auth_required
    def api_remove_entry(service):
        removed = vault.remove_entry(g.user_id, g.key, service, app.config["DB_PATH"])
        if not removed:
            return jsonify({"error": f"No entry found for '{service}'"}), 404
        return jsonify({"message": f"Removed entry for '{service}'"})

    @app.route("/api/generate-password", methods=["POST"])
    @auth_required
    def api_generate_password():
        data = request.get_json(silent=True) or {}
        length = int(data.get("length", 20))
        use_symbols = bool(data.get("use_symbols", True))
        length = max(8, min(length, 128))
        password = crypto_utils.generate_password(length=length, use_symbols=use_symbols)
        return jsonify({"password": password})

    @app.route("/api/change-master-password", methods=["POST"])
    @auth_required
    def api_change_master_password():
        data = request.get_json(silent=True) or {}
        new_master_password = data.get("new_master_password") or ""
        if len(new_master_password) < 8:
            return jsonify({"error": "New master password must be at least 8 characters"}), 400
        new_key = vault.change_master_password(g.user_id, g.key, new_master_password, app.config["DB_PATH"])
        old_token = session.get("token")
        if old_token:
            session_store.destroy_session(old_token)
        new_token = session_store.create_session(g.user_id, g.username, new_key)
        session["token"] = new_token
        return jsonify({"message": "Master password changed. Vault re-encrypted."})

    @app.errorhandler(InvalidTag)
    def handle_invalid_tag(e):
        return jsonify({"error": "Decryption failed. Vault data may be corrupted."}), 500

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1", port=5000)
