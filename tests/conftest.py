import os
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


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def admin_password():
    return os.environ["ADMIN_PASSWORD"]


@pytest.fixture()
def logged_client(client, admin_password):
    client.post("/login", data={"username": "admin", "password": admin_password})
    return client
