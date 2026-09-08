import json
from cryptography.exceptions import InvalidTag
from . import crypto_utils, db

VERIFIER_PLAINTEXT = b"pyvault-verifier-do-not-change"
class VaultError(Exception): pass
class UsernameTaken(VaultError): pass
class InvalidCredentials(VaultError): pass
class UserNotFound(VaultError): pass

def register_user(username, master_password, db_path=None):
    username = username.strip()
    if not username: raise ValueError("Username cannot be empty")
    if not master_password: raise ValueError("Master password cannot be empty")
    if db.username_exists(username, db_path): raise UsernameTaken(f"Username '{username}' is already taken")
    salt = crypto_utils.generate_salt()
    key = crypto_utils.derive_key(master_password, salt)
    verifier = crypto_utils.encrypt(key, VERIFIER_PLAINTEXT)
    empty_vault = crypto_utils.encrypt(key, json.dumps({}).encode("utf-8"))
    return db.create_user(username, salt, crypto_utils.PBKDF2_ITERATIONS, verifier, empty_vault, db_path)

def authenticate(username, master_password, db_path=None):
    user = db.get_user_by_username(username, db_path)
    if user is None: raise InvalidCredentials("Invalid username or master password")
    key = crypto_utils.derive_key(master_password, user["salt"], user["iterations"])
    try:
        if crypto_utils.decrypt(key, user["verifier"]) != VERIFIER_PLAINTEXT:
            raise InvalidCredentials("Invalid username or master password")
    except InvalidTag:
        raise InvalidCredentials("Invalid username or master password")
    return user["id"], user["username"], key

def _load_entries(user_id, key, db_path=None):
    user = db.get_user_by_id(user_id, db_path)
    if user is None: raise UserNotFound("User no longer exists")
    return json.loads(crypto_utils.decrypt(key, user["vault_data"]).decode("utf-8"))

def _save_entries(user_id, key, entries, db_path=None):
    db.update_vault_data(user_id, crypto_utils.encrypt(key, json.dumps(entries).encode("utf-8")), db_path)

def list_services(user_id, key, db_path=None): return sorted(_load_entries(user_id, key, db_path).keys())
def get_entry(user_id, key, service, db_path=None): return _load_entries(user_id, key, db_path).get(service)

def add_entry(user_id, key, service, username, password, notes="", db_path=None):
    entries = _load_entries(user_id, key, db_path)
    entries[service] = {"username": username, "password": password, "notes": notes}
    _save_entries(user_id, key, entries, db_path)

def remove_entry(user_id, key, service, db_path=None):
    entries = _load_entries(user_id, key, db_path)
    if service in entries:
        del entries[service]; _save_entries(user_id, key, entries, db_path); return True
    return False

def change_master_password(user_id, old_key, new_master_password, db_path=None):
    entries = _load_entries(user_id, old_key, db_path)
    new_salt = crypto_utils.generate_salt()
    new_key = crypto_utils.derive_key(new_master_password, new_salt)
    new_verifier = crypto_utils.encrypt(new_key, VERIFIER_PLAINTEXT)
    new_vault_blob = crypto_utils.encrypt(new_key, json.dumps(entries).encode("utf-8"))
    db.update_master_credentials(user_id, new_salt, crypto_utils.PBKDF2_ITERATIONS, new_verifier, new_vault_blob, db_path)
    return new_key
