import os
import re
import tempfile

import pytest

# Configuracao de teste ANTES de importar a aplicacao: o app le estas
# variaveis na importacao. Valores aleatorios gerados por execucao, nunca
# credenciais reais.
_tmpdir = tempfile.mkdtemp(prefix="taskflow-test-")
os.environ["TASKFLOW_SECRET_KEY"] = os.urandom(32).hex()
os.environ["ADMIN_PASSWORD"] = os.urandom(12).hex()
os.environ["TASKFLOW_DB_PATH"] = os.path.join(_tmpdir, "test.db")

from app import app as flask_app  # noqa: E402
from app import init_db  # noqa: E402


@pytest.fixture()
def app():
    flask_app.config.update(TESTING=True)
    if os.path.exists(os.environ["TASKFLOW_DB_PATH"]):
        os.remove(os.environ["TASKFLOW_DB_PATH"])
    with flask_app.app_context():
        init_db()
    yield flask_app


_CSRF_INPUT = re.compile(rb'name="csrf_token" value="([^"]+)"')


def csrf_from(client, path):
    """Le o token anti-CSRF do formulario, como faria um navegador."""
    match = _CSRF_INPUT.search(client.get(path).data)
    assert match, f"formulario em {path} sem csrf_token"
    return match.group(1).decode()


def post_form(client, path, data):
    """POST com o token CSRF obtido do proprio formulario."""
    return client.post(path, data={**data, "csrf_token": csrf_from(client, path)})


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def admin_password():
    return os.environ["ADMIN_PASSWORD"]


@pytest.fixture()
def logged_client(client, admin_password):
    post_form(client, "/login", {"username": "admin", "password": admin_password})
    return client
