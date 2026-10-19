#!/usr/bin/env bash
# Sobe a imagem endurecida da TaskFlow com flags de seguranca em runtime.
#
# Uso:
#   docker build -t taskflow:hardened .
#   cp .env.example .env    # e preencha os valores
#   ./scripts/docker-run-seguro.sh
#
# Variaveis opcionais: IMAGE (padrao taskflow:hardened), CONTAINER_NAME,
# HOST_PORT (padrao 5000), ENV_FILE (padrao .env).
set -euo pipefail

IMAGE="${IMAGE:-taskflow:hardened}"
CONTAINER_NAME="${CONTAINER_NAME:-taskflow-seguro}"
HOST_PORT="${HOST_PORT:-5000}"
ENV_FILE="${ENV_FILE:-.env}"
VOLUME_NAME="${VOLUME_NAME:-taskflow-dados}"

# Segredos: lidos de um arquivo .env fora do versionamento OU de variaveis ja
# exportadas no shell. Com "-e NOME" (sem "=valor") o Docker copia o valor do
# ambiente, entao o segredo nao aparece na linha de comando nem no "ps".
secret_args=()
if [[ -f "$ENV_FILE" ]]; then
  secret_args+=(--env-file "$ENV_FILE")
else
  : "${TASKFLOW_SECRET_KEY:?defina TASKFLOW_SECRET_KEY ou crie $ENV_FILE}"
  : "${ADMIN_PASSWORD:?defina ADMIN_PASSWORD ou crie $ENV_FILE}"
  secret_args+=(-e TASKFLOW_SECRET_KEY -e ADMIN_PASSWORD)
  [[ -n "${ALUNO_PASSWORD:-}" ]] && secret_args+=(-e ALUNO_PASSWORD)
fi

docker volume create "$VOLUME_NAME" >/dev/null

# --read-only                    filesystem raiz somente leitura
# -v volume:/app/data            unico caminho persistente gravavel (SQLite)
# --tmpfs /tmp                   temporarios em memoria, sem exec/suid
# --cap-drop=ALL                 nenhuma Linux capability (porta 5000 > 1024)
# --security-opt no-new-privileges  bloqueia escalonamento via setuid
# --memory / --cpus / --pids-limit  limites contra abuso de recursos
# --user 10001:10001             reforca o usuario nao-root do Dockerfile
# -p 127.0.0.1:...               publica so na interface local do host
# (--privileged nunca e usado)
docker run \
  --name "$CONTAINER_NAME" \
  --rm \
  --detach \
  --read-only \
  -v "${VOLUME_NAME}:/app/data" \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --memory=256m \
  --cpus=0.5 \
  --pids-limit=100 \
  --user 10001:10001 \
  -p "127.0.0.1:${HOST_PORT}:5000" \
  "${secret_args[@]}" \
  "$IMAGE"

echo "Container '$CONTAINER_NAME' iniciado a partir de '$IMAGE'."
echo "Teste:  curl -i http://127.0.0.1:${HOST_PORT}/login"
echo "Logs:   docker logs -f $CONTAINER_NAME"
echo "Parar:  docker stop $CONTAINER_NAME"
