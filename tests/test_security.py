"""Testes de regressao das vulnerabilidades corrigidas na TaskFlow."""

import os
import sqlite3


def test_login_valido_redireciona_para_tarefas(client, admin_password):
    resp = client.post("/login", data={"username": "admin", "password": admin_password})
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/tasks")


def test_login_com_senha_errada_falha(client):
    resp = client.post("/login", data={"username": "admin", "password": "errada"})
    assert resp.status_code == 200
    assert b"invalidos" in resp.data


def test_sql_injection_no_login_nao_autentica(client):
    for payload in ["admin' --", "' OR '1'='1"]:
        resp = client.post("/login", data={"username": payload, "password": "x"})
        assert resp.status_code == 200, payload
        assert b"invalidos" in resp.data


def test_senhas_armazenadas_com_hash(app, admin_password):
    db = sqlite3.connect(os.environ["TASKFLOW_DB_PATH"])
    stored = db.execute("SELECT password FROM users WHERE username = 'admin'").fetchone()[0]
    db.close()
    assert stored != admin_password
    assert stored.startswith(("scrypt:", "pbkdf2:"))


def test_sql_injection_na_busca_nao_vaza_dados(logged_client):
    logged_client.post("/tasks/new", data={"title": "minha", "description": "d"})
    resp = logged_client.get("/tasks", query_string={"q": "' OR '1'='1"})
    assert resp.status_code == 200
    assert b"minha" not in resp.data


def test_xss_armazenado_e_escapado(logged_client):
    payload = "<script>alert(1)</script>"
    logged_client.post("/tasks/new", data={"title": "xss", "description": payload})
    resp = logged_client.get("/tasks")
    assert payload.encode() not in resp.data
    assert b"&lt;script&gt;" in resp.data


def test_endpoint_de_debug_removido(client):
    assert client.get("/debug/info").status_code == 404


def test_cookie_de_sessao_httponly(client, admin_password):
    resp = client.post("/login", data={"username": "admin", "password": admin_password})
    assert "HttpOnly" in resp.headers.get("Set-Cookie", "")
