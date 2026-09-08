def test_vault_lifecycle(tmp_path):
    from password_manager import db, session_store, vault
    path = str(tmp_path / "test.db")
    db.init_db(path)
    user_id = vault.register_user("alice", "strong-password", path)
    uid, username, key = vault.authenticate("alice", "strong-password", path)
    assert uid == user_id and username == "alice"
    vault.add_entry(uid, key, "github", "alice", "secret", "notes", path)
    assert vault.list_services(uid, key, path) == ["github"]
    assert vault.get_entry(uid, key, "github", path)["password"] == "secret"
    assert vault.remove_entry(uid, key, "github", path)
    assert vault.list_services(uid, key, path) == []
    session_store.clear_all_sessions()

def test_duplicate_username_rejected(tmp_path):
    from password_manager import db, vault
    path = str(tmp_path / "test.db")
    db.init_db(path)
    vault.register_user("alice", "strong-password", path)
    try:
        vault.register_user("alice", "another-password", path)
        assert False
    except vault.UsernameTaken:
        pass
