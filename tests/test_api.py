def test_api_auth_and_entries(tmp_path):
    from app import create_app
    from password_manager import session_store
    app = create_app(str(tmp_path / "api.db"))
    client = app.test_client()
    r = client.post("/api/register", json={"username":"bob","master_password":"strong-password"})
    assert r.status_code == 201
    r = client.post("/api/login", json={"username":"bob","master_password":"strong-password"})
    assert r.status_code == 200
    assert client.get("/api/me").json["authenticated"] is True
    assert client.post("/api/entries", json={"service":"example","username":"bob","password":"pw","notes":"n"}).status_code == 201
    assert client.get("/api/entries/example").json["password"] == "pw"
    assert client.delete("/api/entries/example").status_code == 200
    client.post("/api/logout")
    assert client.get("/api/entries").status_code == 401
    session_store.clear_all_sessions()
