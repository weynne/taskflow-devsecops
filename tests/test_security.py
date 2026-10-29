"""Testes de regressao das vulnerabilidades corrigidas na TaskFlow."""

import io
import json
import logging
import os
import pathlib
import re
import sqlite3

from app import JsonFormatter, logger
from conftest import post_form


def test_login_valido_redireciona_para_tarefas(client, admin_password):
    resp = post_form(client, "/login", {"username": "admin", "password": admin_password})
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/tasks")


def test_login_com_senha_errada_falha(client):
    resp = post_form(client, "/login", {"username": "admin", "password": "errada"})
    assert resp.status_code == 200
    assert b"invalidos" in resp.data


def test_sql_injection_no_login_nao_autentica(client):
    for payload in ["admin' --", "' OR '1'='1"]:
        resp = post_form(client, "/login", {"username": payload, "password": "x"})
        assert resp.status_code == 200, payload
        assert b"invalidos" in resp.data


def test_senhas_armazenadas_com_hash(app, admin_password):
    db = sqlite3.connect(os.environ["TASKFLOW_DB_PATH"])
    stored = db.execute("SELECT password FROM users WHERE username = 'admin'").fetchone()[0]
    db.close()
    assert stored != admin_password
    assert stored.startswith(("scrypt:", "pbkdf2:"))


def test_sql_injection_na_busca_nao_vaza_dados(logged_client):
    post_form(logged_client, "/tasks/new", {"title": "minha", "description": "d"})
    resp = logged_client.get("/tasks", query_string={"q": "' OR '1'='1"})
    assert resp.status_code == 200
    assert b"minha" not in resp.data


def test_xss_armazenado_e_escapado(logged_client):
    payload = "<script>alert(1)</script>"
    post_form(logged_client, "/tasks/new", {"title": "xss", "description": payload})
    resp = logged_client.get("/tasks")
    assert payload.encode() not in resp.data
    assert b"&lt;script&gt;" in resp.data


def test_endpoint_de_debug_removido(client):
    assert client.get("/debug/info").status_code == 404


def test_cookie_de_sessao_httponly(client, admin_password):
    resp = post_form(client, "/login", {"username": "admin", "password": admin_password})
    assert "HttpOnly" in resp.headers.get("Set-Cookie", "")


# --- Atividade 2: DAST (Modulo 4) -------------------------------------------


def test_xss_refletido_no_parametro_q_e_escapado(logged_client):
    payload = '"><script>alert(1)</script>'
    resp = logged_client.get("/tasks", query_string={"q": payload})
    assert payload.encode() not in resp.data
    assert b"&#34;&gt;&lt;script&gt;" in resp.data


def test_templates_nao_desligam_o_autoescape():
    # Regressao do XSS: "| safe", "Markup" ou "autoescape false" reabririam o sink.
    proibido = re.compile(r"\|\s*safe\b|autoescape\s+false|Markup\(")
    for template in pathlib.Path("templates").glob("*.html"):
        assert not proibido.search(template.read_text()), template


def test_debug_desligado_por_padrao(app):
    assert app.debug is False


def test_cabecalhos_de_seguranca_presentes(client):
    resp = client.get("/login")
    assert "default-src 'none'" in resp.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"


def test_post_sem_token_csrf_e_rejeitado(logged_client):
    resp = logged_client.post("/tasks/new", data={"title": "t", "description": "d"})
    assert resp.status_code == 400


def test_login_sem_token_csrf_e_rejeitado(client, admin_password):
    resp = client.post("/login", data={"username": "admin", "password": admin_password})
    assert resp.status_code == 400


# --- Atividade 2: observabilidade (Modulo 6) --------------------------------


def _capturar_logs():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    return stream, handler


def test_logs_em_json_com_request_id_e_sem_senha(client, admin_password):
    stream, handler = _capturar_logs()
    try:
        post_form(client, "/login", {"username": "admin", "password": "senha-errada-123"})
        post_form(client, "/login", {"username": "admin", "password": admin_password})
        client.get("/tasks")
    finally:
        logger.removeHandler(handler)

    saida = stream.getvalue()
    assert admin_password not in saida
    assert "senha-errada-123" not in saida
    eventos = [json.loads(linha) for linha in saida.splitlines()]
    assert all(e["request_id"] for e in eventos)
    nomes = [e["event"] for e in eventos]
    for esperado in ("login_failure", "login_success", "tasks_listed", "http_request"):
        assert esperado in nomes
    falha = next(e for e in eventos if e["event"] == "login_failure")
    assert falha["user"] == "admin" and falha["reason"] == "bad_password"
    assert "client_ip" in falha


def test_campos_sensiveis_sao_descartados_do_log():
    stream, handler = _capturar_logs()
    try:
        logger.info("teste", extra={"fields": {"password": "x1", "session_cookie": "x2", "ok": 1}})
    finally:
        logger.removeHandler(handler)
    evento = json.loads(stream.getvalue())
    assert "password" not in evento and "session_cookie" not in evento
    assert evento["ok"] == 1


def test_request_id_e_devolvido_e_valida_formato(client):
    resp = client.get("/login", headers={"X-Request-ID": "abc12345-proxy"})
    assert resp.headers["X-Request-ID"] == "abc12345-proxy"
    resp = client.get("/login", headers={"X-Request-ID": "<script>alert(1)</script>"})
    assert re.fullmatch(r"[0-9a-f]{32}", resp.headers["X-Request-ID"])
