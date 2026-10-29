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
  7. debug=True / servidor de dev         -> debug via TASKFLOW_DEBUG (desligado
                                             por padrao), gunicorn na imagem

Atividade 2 (DAST e observabilidade):
  8. Cabecalhos de seguranca ausentes     -> CSP, anti-clickjacking, nosniff etc.
  9. Formularios sem token anti-CSRF      -> token por sessao validado em todo POST
 10. Sem trilha de auditoria              -> logs JSON com request_id por requisicao

Variaveis de ambiente:
  TASKFLOW_SECRET_KEY  (obrigatoria) chave de assinatura da sessao
  ADMIN_PASSWORD       (obrigatoria na criacao do banco) senha inicial do admin
  ALUNO_PASSWORD       (opcional) cria o usuario "aluno" com esta senha
  TASKFLOW_DB_PATH     (opcional) caminho do SQLite, padrao "taskflow.db"
  TASKFLOW_DEBUG       (opcional) "1" liga o modo debug no servidor de dev;
                       qualquer outro valor (ou ausente) mantem desligado
  TASKFLOW_LOG_LEVEL   (opcional) nivel de log, padrao INFO
"""

import json
import logging
import os
import re
import secrets
import sqlite3
import sys
import time
import uuid
from datetime import datetime, timezone

from flask import (
    Flask,
    abort,
    g,
    has_request_context,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
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


# -----------------------------------------------------------------------------
# Logging estruturado (Modulo 6)
# -----------------------------------------------------------------------------
# Uma linha JSON por evento no stdout: o Docker guarda, o Promtail coleta e o
# Loki indexa. Todo evento emitido durante uma requisicao carrega o mesmo
# request_id, o que permite reconstruir o caminho de uma requisicao no Grafana.
#
# Nada sensivel e logado: nunca request.form inteiro, senha, cookie, token ou
# cabecalho Authorization. Como defesa em profundidade, o formatter descarta
# qualquer campo cujo NOME pareca sensivel, mesmo que alguem o passe por engano.
_SENSITIVE_FIELD = re.compile(r"pass|secret|token|cookie|authorization|csrf", re.IGNORECASE)
_REQUEST_ID_FORMAT = re.compile(r"^[A-Za-z0-9-]{8,64}$")


class JsonFormatter(logging.Formatter):
    def format(self, record):
        entry = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        if has_request_context():
            entry["request_id"] = getattr(g, "request_id", None)
        for key, value in getattr(record, "fields", {}).items():
            if not _SENSITIVE_FIELD.search(key):
                entry[key] = value
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        # json.dumps escapa quebras de linha e aspas: um username como
        # "x\n{...}" nao consegue forjar uma linha de log falsa (log injection).
        return json.dumps(entry, ensure_ascii=False)


logger = logging.getLogger("taskflow")
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(JsonFormatter())
logger.addHandler(_handler)
logger.setLevel(os.environ.get("TASKFLOW_LOG_LEVEL", "INFO").upper())
logger.propagate = False


def log_event(event, level=logging.INFO, **fields):
    """Registra um evento de negocio/seguranca como uma linha JSON."""
    logger.log(level, event, extra={"fields": fields})


def client_ip():
    # Sem proxy reverso na frente, remote_addr e o IP real do cliente. Se um
    # proxy for adicionado, use werkzeug.middleware.proxy_fix.ProxyFix com o
    # numero exato de saltos confiaveis, nunca X-Forwarded-For cru (forjavel).
    return request.remote_addr


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

# Cabecalhos de seguranca enviados em toda resposta (achados do ZAP Baseline,
# ver docs/dast.md). A CSP so permite recursos do proprio dominio e nenhum
# script: mesmo que um XSS escape do autoescape, o navegador nao o executa.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'self'; img-src 'self'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    # Paginas com dados do usuario nao devem ficar em cache compartilhado.
    "Cache-Control": "no-store",
}


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


@app.before_request
def start_request():
    # Reaproveita o X-Request-ID de um proxy/cliente apenas se tiver formato
    # seguro; caso contrario gera um novo. Assim o id nao vira vetor de injecao.
    incoming = request.headers.get("X-Request-ID", "")
    g.request_id = incoming if _REQUEST_ID_FORMAT.match(incoming) else uuid.uuid4().hex
    g.start_time = time.perf_counter()


@app.before_request
def csrf_protect():
    # CORRIGIDO (ausencia de token anti-CSRF, achado do ZAP): todo POST precisa
    # devolver o token guardado na sessao. Comparacao em tempo constante.
    if request.method == "POST":
        expected = session.get("csrf_token")
        received = request.form.get("csrf_token", "")
        if not expected or not secrets.compare_digest(expected, received):
            log_event(
                "csrf_rejected", logging.WARNING, path=request.path, client_ip=client_ip()
            )
            abort(400)


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.after_request
def finish_request(response):
    for header, value in SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    response.headers["X-Request-ID"] = g.request_id
    # Apenas o caminho, sem query string: parametros podem carregar dados do
    # usuario e nao sao necessarios para as consultas de observabilidade.
    log_event(
        "http_request",
        method=request.method,
        path=request.path,
        status=response.status_code,
        duration_ms=round((time.perf_counter() - g.start_time) * 1000, 2),
        client_ip=client_ip(),
        user_id=session.get("user_id"),
    )
    return response


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
            log_event(
                "login_success", user=user["username"], user_id=user["id"], client_ip=client_ip()
            )
            return redirect(url_for("tasks"))
        # So o username (truncado) e o motivo; a senha digitada NUNCA e logada.
        # O motivo fica no log interno, mas a mensagem ao usuario e a mesma nos
        # dois casos para nao revelar quais usuarios existem.
        log_event(
            "login_failure",
            logging.WARNING,
            user=username[:64],
            reason="bad_password" if user else "unknown_user",
            client_ip=client_ip(),
        )
        error = "Usuario ou senha invalidos."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    if "user_id" in session:
        log_event("logout", user_id=session["user_id"], client_ip=client_ip())
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

    log_event(
        "tasks_listed",
        user_id=session["user_id"],
        count=len(rows),
        search_used=bool(search),
        client_ip=client_ip(),
    )
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
        cur = db.execute(
            "INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)",
            (session["user_id"], title, description),
        )
        db.commit()
        # Conteudo da tarefa nao e logado (pode ter dado pessoal): so metadados.
        log_event(
            "task_created",
            user_id=session["user_id"],
            task_id=cur.lastrowid,
            title_length=len(title),
            client_ip=client_ip(),
        )
        return redirect(url_for("tasks"))

    return render_template("new_task.html")


# CORRIGIDO (endpoint de debug exposto): a rota /debug/info, que devolvia a
# SECRET_KEY e detalhes do servidor sem autenticacao, foi removida.


if __name__ == "__main__":
    # Apenas para desenvolvimento local. Em producao a imagem usa gunicorn
    # (wsgi.py), que nunca liga o debugger. O bind padrao e somente local.
    # CORRIGIDO (debug=True): o modo debug expoe o console interativo do
    # Werkzeug (execucao remota de codigo). Agora so liga com TASKFLOW_DEBUG=1,
    # explicitamente, e fica DESLIGADO por padrao.
    with app.app_context():
        init_db()
    app.run(
        host=os.environ.get("TASKFLOW_HOST", "127.0.0.1"),
        port=5000,
        debug=os.environ.get("TASKFLOW_DEBUG", "0") == "1",
    )
