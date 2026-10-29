#!/usr/bin/env bash
# DAST da TaskFlow com o OWASP ZAP, contra uma instancia JA em execucao.
# Usado pelo workflow .github/workflows/dast.yml e tambem localmente (plano B
# da demo):
#
#   ./scripts/docker-run-seguro.sh          # com ALUNO_PASSWORD definido
#   DAST_PASSWORD="$ALUNO_PASSWORD" ./scripts/dast-scan.sh
#
# Etapas (qualquer uma falhando encerra com erro):
#   1. Espera ativa ate /login responder com a pagina da TaskFlow, para o ZAP
#      nunca "atacar o nada" e devolver um relatorio falsamente limpo.
#   2. Login real (com token CSRF) e prova de que a sessao abre /tasks.
#   3. ZAP Baseline (passivo, spider autenticado) com gate em .zap/rules.tsv.
#   4. Varredura ativa somente de XSS (.zap/xss-active.yaml), com gate em
#      qualquer alerta de XSS de risco Medium ou maior.
#
# Variaveis: DAST_PASSWORD (obrigatoria), TARGET, DAST_USER, ZAP_IMAGE,
# REPORT_DIR, WAIT_TIMEOUT, MIN_URLS.
set -euo pipefail

TARGET="${TARGET:-http://127.0.0.1:5000}"
DAST_USER="${DAST_USER:-aluno}"
: "${DAST_PASSWORD:?defina DAST_PASSWORD com a senha do usuario $DAST_USER}"
ZAP_IMAGE="${ZAP_IMAGE:-zaproxy/zap-stable}"
REPORT_DIR="${REPORT_DIR:-reports/zap}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-60}"
# O spider autenticado precisa enxergar ao menos /login, /tasks, /tasks/new e
# o CSS. Menos do que isso indica que a sessao nao funcionou.
MIN_URLS="${MIN_URLS:-4}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$REPORT_DIR"
REPORT_DIR="$(cd "$REPORT_DIR" && pwd)"
# O container do ZAP roda com outro UID e precisa escrever os relatorios.
chmod 777 "$REPORT_DIR"
cp "$ROOT/.zap/rules.tsv" "$ROOT/.zap/xss-active.yaml" "$REPORT_DIR/"

echo "==> 1/4 Aguardando $TARGET/login (ate ${WAIT_TIMEOUT}s)"
deadline=$((SECONDS + WAIT_TIMEOUT))
until curl -sf "$TARGET/login" | grep -q "TaskFlow - Login"; do
  if (( SECONDS >= deadline )); then
    echo "::error::A TaskFlow nao respondeu em ${WAIT_TIMEOUT}s; o scan nao vai rodar contra o nada."
    exit 1
  fi
  sleep 2
done
echo "    aplicacao respondendo"

echo "==> 2/4 Abrindo sessao autenticada como '$DAST_USER'"
jar="$(mktemp)"
trap 'rm -f "$jar"' EXIT
token="$(curl -sf -c "$jar" -b "$jar" "$TARGET/login" \
  | sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p')"
status="$(curl -s -o /dev/null -w '%{http_code}' -c "$jar" -b "$jar" \
  --data-urlencode "csrf_token=$token" \
  --data-urlencode "username=$DAST_USER" \
  --data-urlencode "password=$DAST_PASSWORD" \
  "$TARGET/login")"
# Abre um formulario ja autenticado para o token CSRF entrar na sessao. O ZAP
# envia sempre este mesmo cookie (a sessao do Flask e assinada e sem estado no
# servidor), entao o token precisa estar nele; sem isso todo POST do ZAP volta
# 400 e o XSS armazenado de /tasks/new nunca seria testado.
curl -sf -o /dev/null -c "$jar" -b "$jar" "$TARGET/tasks/new" || true
cookie="$(awk '$6 == "session" {print $7}' "$jar")"
if [[ "$status" != "302" || -z "$cookie" ]] \
   || ! curl -sf -b "session=$cookie" "$TARGET/tasks" | grep -q "Minhas tarefas"; then
  echo "::error::Login do DAST falhou (HTTP $status); o scan autenticado nao provaria nada."
  exit 1
fi
# A sessao e um segredo efemero: nao deve aparecer no log do Actions.
[[ -n "${GITHUB_ACTIONS:-}" ]] && echo "::add-mask::$cookie"
echo "    sessao autenticada valida"

zap_run() {
  docker run --rm --network host -v "$REPORT_DIR:/zap/wrk:rw" -e TARGET "$ZAP_IMAGE" "$@"
}
export TARGET

# Regra do Replacer do ZAP: toda requisicao sai com o cookie da sessao
# autenticada, inclusive as do spider e as de ataque.
replacer=(
  -config "replacer.full_list(0).description=sessao"
  -config "replacer.full_list(0).enabled=true"
  -config "replacer.full_list(0).matchtype=REQ_HEADER"
  -config "replacer.full_list(0).matchstr=Cookie"
  -config "replacer.full_list(0).regex=false"
  -config "replacer.full_list(0).replacement=session=$cookie"
)

echo "==> 3/4 ZAP Baseline (gate: .zap/rules.tsv)"
# Codigos de saida do zap-baseline.py: 0 ok, 1 FAIL, 2 so WARN, 3 erro.
# -I faz WARN (regra rebaixada e justificada no rules.tsv) nao quebrar o job;
# FAIL e erro quebram. Nao ha continue-on-error: o gate e este exit code.
set +e
zap_run zap-baseline.py -t "$TARGET" -c rules.tsv -I \
  -r zap-baseline.html -w zap-baseline.md -J zap-baseline.json \
  -z "${replacer[*]}" | tee "$REPORT_DIR/zap-baseline.log"
baseline_rc=${PIPESTATUS[0]}
set -e

urls="$(sed -n 's/^Total of \([0-9]*\) URLs.*/\1/p' "$REPORT_DIR/zap-baseline.log" | tail -1)"
if (( ${urls:-0} < MIN_URLS )); then
  echo "::error::Spider encontrou ${urls:-0} URLs (minimo $MIN_URLS): o scan nao cobriu a aplicacao."
  exit 1
fi
if (( baseline_rc != 0 )); then
  echo "::error::ZAP Baseline reprovou (exit $baseline_rc). Veja zap-baseline.html."
  exit 1
fi

echo "==> 4/4 ZAP varredura ativa de XSS (gate: risco >= Medium)"
zap_run zap.sh -cmd "${replacer[@]}" -autorun /zap/wrk/xss-active.yaml | tee "$REPORT_DIR/zap-xss.log"
if [[ ! -s "$REPORT_DIR/zap-xss.json" ]]; then
  echo "::error::Relatorio da varredura de XSS nao foi gerado."
  exit 1
fi
xss="$(jq -r '[.site[].alerts[] | select((.pluginid | tonumber) as $id
         | [40012, 40014, 40016, 40017] | index($id))
         | select((.riskcode | tonumber) >= 2)]
       | map("\(.alert) [\(.riskdesc)] em \(.instances[0].uri)") | .[]' \
       "$REPORT_DIR/zap-xss.json")"
if [[ -n "$xss" ]]; then
  echo "::error::ZAP confirmou XSS:"
  echo "$xss"
  exit 1
fi

echo "OK: Baseline aprovado ($urls URLs) e nenhum XSS encontrado."
