# syntax=docker/dockerfile:1
# Dockerfile endurecido da TaskFlow. Cada "CORRIGIDO (FALHA N)" referencia a
# falha correspondente do Dockerfile original da linha de base.

# -----------------------------------------------------------------------------
# Estagio 1: build - instala as dependencias em um virtualenv isolado
# -----------------------------------------------------------------------------
# CORRIGIDO (FALHA 1): imagem minima (slim) com tag fixa E digest imutavel.
# O digest garante que o build de hoje e o de amanha usam exatamente a mesma
# imagem base; o Dependabot (ecossistema docker) propoe a atualizacao.
FROM python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704 AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY requirements.txt .

# CORRIGIDO (FALHA 3): --require-hashes confere o sha256 de cada pacote
# (requirements.txt e gerado com hashes pelo pip-compile). Um pacote adulterado
# no indice, ou uma dependencia nao declarada, faz o build falhar.
# O pip e removido do venv no fim: nao e necessario em runtime.
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --require-hashes -r requirements.txt \
    && /opt/venv/bin/pip uninstall -y pip

# -----------------------------------------------------------------------------
# Estagio 2: runtime - somente o necessario para executar a aplicacao
# -----------------------------------------------------------------------------
FROM python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704 AS runtime

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TASKFLOW_DB_PATH=/app/data/taskflow.db

# CORRIGIDO (FALHA 2): usuario e grupo dedicados, sem shell e sem privilegios.
# UID/GID fixos (10001) para poder reforcar com "docker run --user".
# O pip do sistema tambem e removido da imagem final (menos superficie).
RUN groupadd --system --gid 10001 taskflow \
    && useradd --system --uid 10001 --gid taskflow --no-create-home \
       --home-dir /nonexistent --shell /usr/sbin/nologin taskflow \
    && python -m pip uninstall -y pip \
    && mkdir -p /app/data \
    && chown taskflow:taskflow /app/data

WORKDIR /app

COPY --from=build /opt/venv /opt/venv
# O codigo pertence ao root e e somente leitura para o usuario da aplicacao:
# mesmo com execucao de codigo, o processo nao consegue alterar a aplicacao.
# Apenas /app/data (banco SQLite) e gravavel pelo usuario taskflow.
COPY app.py wsgi.py ./
COPY templates/ templates/
COPY static/ static/

# CORRIGIDO (FALHA 4): nenhum segredo em ENV/ARG. TASKFLOW_SECRET_KEY e
# ADMIN_PASSWORD sao injetados em tempo de execucao (docker run -e / secrets
# do orquestrador) e por isso nao aparecem em "docker history".

# CORRIGIDO (FALHA 5): EXPOSE apenas documenta a porta; agora quem escuta
# nela e o gunicorn, nao o servidor de desenvolvimento do Flask.
EXPOSE 5000

USER taskflow

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/login', timeout=2)"]

# CORRIGIDO (FALHA 6): servidor WSGI de producao (gunicorn), sem debug e
# como usuario nao-root. --preload inicializa o banco uma unica vez (wsgi.py).
# --worker-tmp-dir em /dev/shm permite rodar com filesystem read-only e
# --no-control-socket desliga o socket de administracao do gunicorn (nao
# usado aqui; seria mais uma interface exposta dentro do container).
# Sem --access-logfile: a propria aplicacao emite um evento JSON
# "http_request" por requisicao (com request_id), e o stdout fica 100% JSON
# para o Promtail/Loki (Modulo 6).
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--preload", \
     "--worker-tmp-dir", "/dev/shm", "--no-control-socket", \
     "wsgi:app"]
