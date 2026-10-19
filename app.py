"""
TaskFlow - gerenciador de tarefas da disciplina DevSecOps.

Versao corrigida pela esteira do grupo a partir da linha de base vulneravel
(app-exemplo/ do repositorio da disciplina). Cada correcao esta marcada com
um comentario "CORRIGIDO" no ponto em que a falha existia:

  1. SQL Injection no login e na busca   -> consultas parametrizadas
  2. XSS armazenado na descricao          -> templates Jinja2 com autoescape
  3. SECRET_KEY hardcoded                 -> variavel de ambiente obrigatoria
  4. Senhas em texto puro                 -> hash (werkzeug.security)
  5. Endpoint /debug/info exposto         -> removido
  6. Dependencias com CVEs                -> requirements.txt atualizado (SCA)
  7. debug=True / servidor de dev         -> debug desligado, gunicorn na imagem

Variaveis de ambiente:
  TASKFLOW_SECRET_KEY  (obrigatoria) chave de assinatura da sessao
  ADMIN_PASSWORD       (obrigatoria na criacao do banco) senha inicial do admin
  ALUNO_PASSWORD       (opcional) cria o usuario "aluno" com esta senha
  TASKFLOW_DB_PATH     (opcional) caminho do SQLite, padrao "taskflow.db"
"""

import os
import sqlite3

from flask import Flask, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


def _required_env(name):
    """Le uma variavel de ambiente obrigatoria ou falha na inicializacao.

    Falhar alto e preferivel a cair silenciosamente para um valor fixo,
    o que reintroduziria o segredo hardcoded de forma escondida.
    """
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"Variavel de ambiente {name} nao foi definida. "
            f"Configure-a antes de iniciar a aplicacao."
        )
    return value


app = Flask(__name__)

# CORRIGIDO (SECRET_KEY hardcoded): o segredo vem do ambiente em runtime
# (export local, secret do repositorio no CI ou docker run -e).
app.config["SECRET_KEY"] = _required_env("TASKFLOW_SECRET_KEY")
# Cookie de sessao inacessivel via JavaScript e nao enviado em requisicoes
# cross-site. SESSION_COOKIE_SECURE deve ser ligado quando houver HTTPS.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("TASKFLOW_COOKIE_SECURE") == "1"

DATABASE = os.environ.get("TASKFLOW_DB_PATH", "taskflow.db")


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            done INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        """
    )
    db.commit()

    cur = db.execute("SELECT COUNT(*) AS total FROM users")
    if cur.fetchone()["total"] == 0:
        # CORRIGIDO (senha em texto puro): o banco guarda apenas o hash
        # (scrypt com salt aleatorio, padrao do Werkzeug). As senhas iniciais
        # nao ficam mais no codigo: sao injetadas em runtime.
        seed_users = [("admin", _required_env("ADMIN_PASSWORD"))]
        aluno_password = os.environ.get("ALUNO_PASSWORD")
        if aluno_password:
            seed_users.append(("aluno", aluno_password))
        db.executemany(
            "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
            [(user, generate_password_hash(pwd)) for user, pwd in seed_users],
        )
        db.commit()


@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("tasks"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # CORRIGIDO (SQL Injection): consulta parametrizada. O driver sqlite3
        # envia os valores separados do comando SQL, entao um payload como
        # "admin' --" e tratado como dado e nunca altera a estrutura da query.
        db = get_db()
        cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()

        # Com a senha em hash, a comparacao e feita por check_password_hash.
        if user and check_password_hash(user["password"], password):
            # Nova sessao a cada login (evita session fixation).
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("tasks"))
        error = "Usuario ou senha invalidos."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/tasks", methods=["GET"])
def tasks():
    if "user_id" not in session:
        return redirect(url_for("login"))

    search = request.args.get("q", "")
    db = get_db()

    if search:
        # CORRIGIDO (SQL Injection na busca): o padrao do LIKE e montado em
        # Python e enviado inteiro como um unico parametro.
        rows = db.execute(
            "SELECT * FROM tasks WHERE user_id = ? AND title LIKE ?",
            (session["user_id"], f"%{search}%"),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM tasks WHERE user_id = ?", (session["user_id"],)
        ).fetchall()

    # CORRIGIDO (XSS armazenado): o HTML deixou de ser montado com f-string.
    # Os templates Jinja2 (.html) tem autoescape ligado, entao um titulo ou
    # descricao como "<script>...</script>" e renderizado como texto.
    return render_template(
        "tasks.html", tasks=rows, username=session["username"], search=search
    )


@app.route("/tasks/new", methods=["GET", "POST"])
def new_task():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form["title"]
        description = request.form["description"]
        db = get_db()
        db.execute(
            "INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)",
            (session["user_id"], title, description),
        )
        db.commit()
        return redirect(url_for("tasks"))

    return render_template("new_task.html")


# CORRIGIDO (endpoint de debug exposto): a rota /debug/info, que devolvia a
# SECRET_KEY e detalhes do servidor sem autenticacao, foi removida.


if __name__ == "__main__":
    # Apenas para desenvolvimento local. Em producao a imagem usa gunicorn
    # (wsgi.py). debug fica desligado e o bind padrao e somente local.
    with app.app_context():
        init_db()
    app.run(host=os.environ.get("TASKFLOW_HOST", "127.0.0.1"), port=5000)
