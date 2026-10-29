# TaskFlow DevSecOps — Esteira Segura

Atividades 1 e 2 da disciplina DevSecOps (CESAR School). A aplicação **TaskFlow** (Flask),
importada propositalmente vulnerável do `app-exemplo/` da disciplina, é protegida por uma
esteira no GitHub Actions que **bloqueia o merge na `main`** quando build, lint, testes,
SAST, secret scanning, SCA, o scan da imagem, o **DAST** (OWASP ZAP contra a app rodando no
runner) ou os **scanners de IaC** (Checkov, Trivy config e a política do Compose) encontram
problemas. A infraestrutura (Docker Compose e Terraform) passa pelo mesmo rigor do código.
Um ataque de força bruta é **detectado nos logs** (Loki + Grafana) e tratado por um
**runbook** NIST SP 800-61.

| Atividade | Conteúdo | Documentação |
| --- | --- | --- |
| 1 | CI, SAST, secret scanning, SCA, hardening do container | [`sast-sca.md`](docs/sast-sca.md), [`hardening.md`](docs/hardening.md) |
| 2 · Módulo 4 | DAST: correção de XSS/debug, ZAP no pipeline, OWASP Top 10 | [`dast.md`](docs/dast.md) |
| 2 · Módulo 5 | IaC: Compose seguro, Terraform corrigido, Checkov/Trivy como gate | [`iac.md`](docs/iac.md) |
| 2 · Módulo 6 | Logs JSON com `request_id`, Grafana + Loki, simulação e runbook | [`observabilidade.md`](docs/observabilidade.md), [`runbook-login-bruteforce.md`](docs/runbook-login-bruteforce.md) |

Grupo **WJD** (o mesmo da disciplina de CI/CD,
[`cicd-grupo-WJD`](https://github.com/weynne/cicd-grupo-WJD)):

| Membro | GitHub | Frente principal |
| --- | --- | --- |
| Weynne Guimarães | [@weynne](https://github.com/weynne) | Dono do repositório: esteira de CI, branch protection, workflow de container |
| Jéssica Camarço | [@jessicacamarco](https://github.com/jessicacamarco) | SAST e secret scanning: Semgrep, Gitleaks, correções no `app.py` e testes |
| Diego Tavares | [@diegotavares16](https://github.com/diegotavares16) | SCA e hardening: pip-audit, Dependabot, Dockerfile, Trivy e Lynis |

Os donos de cada área estão em [`.github/CODEOWNERS`](.github/CODEOWNERS): cada área tem
o mantenedor ao lado do dono do repositório, e toda regra tem no mínimo dois donos.

**Acesso do professor:** @HardSource foi convidado como collaborator. O repositório é de conta
pessoal, e nesse tipo de conta o GitHub não oferece o papel *Read*: todo collaborator recebe
leitura e escrita (*Read* só existe em repositórios de organização). Mesmo assim, ninguém altera
a `main` fora do fluxo, porque a branch protection exige PR e os 7 checks verdes, inclusive para
administradores.

## Arquitetura

```text
                         host (docker compose)
 ┌────────────────────────────────────────────────────────────────────────────────┐
 │ projeto "taskflow" (docker-compose.yml)                                         │
 │                                                                                │
 │  127.0.0.1:5000 ─► web (gunicorn/Flask, UID 10001, read-only, cap_drop ALL)     │
 │                     │  rede frontend                                           │
 │                     │  rede backend (internal: sem saída) ──► db (postgres,     │
 │                     │                                         sem porta no host)│
 │                     └─ stdout: 1 linha JSON por evento (request_id, event, ...) │
 │                              │ driver json-file (attrs: projeto/serviço)        │
 ├──────────────────────────────┼─────────────────────────────────────────────────┤
 │ projeto "taskflow-observabilidade" (docker-compose.observability.yml)           │
 │                              ▼                                                  │
 │  promtail ── lê /var/lib/docker/containers (ro, sem docker.sock)                │
 │     │ push                                                                      │
 │     ▼            rede monitoring                                                │
 │  loki (127.0.0.1:3100) ◄── grafana (127.0.0.1:3000): dashboard + alerta         │
 └────────────────────────────────────────────────────────────────────────────────┘
   infra/ (Terraform, AWS): bucket S3 privado + KMS + versionamento + logging,
   security group restrito a var.allowed_ingress_cidr. Só validate/scan, sem apply.
```

## Visão geral da esteira

```text
PR para main ──┬── CI ────────── Build e lint (ruff + flake8-bandit)
               │                 Testes (pytest: regressão de segurança)
               ├── SAST ──────── SAST - Semgrep (p/python, p/flask, p/security-audit)
               │                 Secret Scanning - Gitleaks (histórico completo)
               ├── SCA ───────── SCA - pip-audit (gate)   SCA - Trivy fs (2ª camada)
               ├── Container ─── Trivy config (Dockerfile) → build → Trivy image
               │                 → sem segredo no docker history → smoke test com runtime seguro
               ├── DAST ──────── build → app sobe no runner → espera /login → login real
               │                 → ZAP Baseline (rules.tsv) → ZAP ativo só XSS
               └── IaC ───────── terraform validate · Checkov · Trivy config · política do Compose
                         │
          todos verdes + 1 aprovação do CODEOWNER ──► merge liberado
```

| Workflow | Gatilhos | O que bloqueia |
| --- | --- | --- |
| [`ci.yml`](.github/workflows/ci.yml) | PR → main, push na main, manual | erro de sintaxe, lint/`S608` (SQL concatenado), `S105` (senha hardcoded), teste de segurança falhando |
| [`sast.yml`](.github/workflows/sast.yml) | PR → main, push na main, manual | qualquer finding do Semgrep (`--error`); qualquer segredo no histórico (Gitleaks) |
| [`sca.yml`](.github/workflows/sca.yml) | PR → main, push na main, **diário**, manual | qualquer CVE conhecida nas dependências (pip-audit); HIGH/CRITICAL no Trivy fs |
| [`container.yml`](.github/workflows/container.yml) | PR → main, push na main, **semanal**, manual | misconfig HIGH/CRITICAL no Dockerfile; CVE HIGH/CRITICAL **com correção** na imagem; segredo em camada; container que não sobe com `--read-only`/`--cap-drop=ALL` |
| [`dast.yml`](.github/workflows/dast.yml) | PR → main, push na main, **semanal**, manual | regra FAIL do ZAP Baseline ([`.zap/rules.tsv`](.zap/rules.tsv)); XSS ≥ Medium na varredura ativa; app que não sobe ou login que falha (o scan nunca roda "contra o nada") |
| [`iac-scan.yml`](.github/workflows/iac-scan.yml) | PR → main, push na main, **semanal**, manual | `terraform fmt`/`validate`; qualquer FAILED do Checkov (Terraform, Dockerfile, Actions); qualquer misconfig do Trivy config; skip sem justificativa; violação da política do Compose |
| [`dependabot.yml`](.github/dependabot.yml) | semanal (GitHub) | abre PRs para pip, GitHub Actions, imagem Docker, imagens do Compose e provider do Terraform |

Boas práticas aplicadas em todos os workflows: `permissions: contents: read` (mínimo);
actions **pinadas por SHA** com a versão em comentário; ferramentas com versão fixa
(Semgrep, pip-audit, ruff, Checkov) e imagens do Trivy, ZAP e Terraform por **digest**; Gitleaks baixado do release
oficial com **checksum sha256 verificado**; `persist-credentials: false` no checkout;
versões e severidades de corte parametrizadas em `env:`; setup do Python reutilizado via
action composta ([`.github/actions/setup-python-deps`](.github/actions/setup-python-deps/action.yml)),
com a versão vinda do arquivo [`.python-version`](.python-version) (fonte única).
Nenhum workflow novo exige secret: o DAST gera senhas e `SECRET_KEY` **efêmeras** dentro do
run (mascaradas no log) e o IaC não usa credencial de nuvem.

## Vulnerabilidades da TaskFlow e onde foram corrigidas

| # | Vulnerabilidade | Detectada por | Correção |
| --- | --- | --- | --- |
| 1 | SQL Injection no login e na busca | Semgrep, ruff `S608` | consultas parametrizadas (`?`) |
| 2 | XSS armazenado | Semgrep | templates Jinja2 com autoescape (`templates/`) |
| 3 | `SECRET_KEY` hardcoded | Semgrep, Gitleaks (regra do grupo) | `TASKFLOW_SECRET_KEY` do ambiente; a app não sobe sem ela |
| 4 | Senhas em texto puro | revisão + testes | hash `werkzeug.security`; senhas iniciais do ambiente |
| 5 | `/debug/info` expõe a `SECRET_KEY` | revisão | rota removida (teste garante 404) |
| 6 | Dependências com CVEs | pip-audit, Trivy | Flask 3.1.3, Werkzeug 3.1.9, Jinja2 3.1.6; árvore com hashes |
| 7 | `debug=True`, bind `0.0.0.0` | Semgrep, ruff | debug removido; gunicorn na imagem |
| 8 | Dockerfile FALHAS 1–6 | Trivy, `docker history` | ver [`docs/hardening.md`](docs/hardening.md) |
| 9 | XSS nos sinks do Encontro 9 (`q` da busca, erro do login) | ZAP (varredura ativa), testes | autoescape, sem `\| safe`; teste que proíbe `\| safe` nos templates |
| 10 | Cabeçalhos de segurança ausentes (CSP, clickjacking, nosniff...) | ZAP Baseline | `after_request` com CSP `default-src 'none'` e demais cabeçalhos |
| 11 | Formulários sem token anti-CSRF | ZAP Baseline (10202) | token por sessão validado em todo POST |
| 12 | `debug` fixo no código | revisão | `TASKFLOW_DEBUG=1` liga explicitamente; desligado por padrão |
| 13 | Sem trilha de auditoria | — | logs JSON com `request_id`, sem dado sensível ([detalhes](docs/observabilidade.md)) |

Detalhes e evidências de antes × depois: [`docs/sast-sca.md`](docs/sast-sca.md),
[`docs/hardening.md`](docs/hardening.md), [`docs/dast.md`](docs/dast.md) (achados mapeados
ao OWASP Top 10 2025) e [`docs/iac.md`](docs/iac.md).

## Evidências de funcionamento

### Atividade 2

| # | Evidência | Link |
| --- | --- | --- |
| 1 | ZAP antes × depois: original (6 FAIL + XSS), Atividade 1 (6 FAIL), Atividade 2 (0 FAIL, 0 XSS) | [`zap-antes.txt`](docs/evidencias/zap-antes.txt) · [`zap-atividade1.txt`](docs/evidencias/zap-atividade1.txt) · [`zap-depois.txt`](docs/evidencias/zap-depois.txt) |
| 2 | Gate do DAST pegando o XSS reaberto com `\| safe` | [`zap-xss-detectado.txt`](docs/evidencias/zap-xss-detectado.txt) |
| 3 | Terraform: Checkov 17 → 0 FAILED, Trivy 13 → 0 | [`checkov-terraform-antes.txt`](docs/evidencias/checkov-terraform-antes.txt) · [`checkov-trivy-terraform-depois.txt`](docs/evidencias/checkov-trivy-terraform-depois.txt) |
| 4 | Compose: política 20 → 0 falhas; isolamento verificado em execução | [`compose-politica.txt`](docs/evidencias/compose-politica.txt) · [`compose-verificacao.txt`](docs/evidencias/compose-verificacao.txt) |
| 5 | Força bruta simulada, detectada pela query do runbook, alerta disparado, contenção executada | [`forca-bruta-deteccao.txt`](docs/evidencias/forca-bruta-deteccao.txt) |
| 6 | Runs de `DAST` e `IaC` no GitHub Actions | *preencher após o PR da Atividade 2* |

### Atividade 1

| # | Evidência | Link |
| --- | --- | --- |
| 1 | Esteira completa verde na `main` (push após o último merge) | [CI](https://github.com/weynne/taskflow-devsecops/actions/runs/39192460252) · [SAST](https://github.com/weynne/taskflow-devsecops/actions/runs/39192460318) · [SCA](https://github.com/weynne/taskflow-devsecops/actions/runs/39192460202) · [Container](https://github.com/weynne/taskflow-devsecops/actions/runs/39192460352) |
| 2 | Shift-left: PR reintroduz SQL Injection no login, ruff (`S608`) e Semgrep (`tainted-sql-string`) ficam vermelhos | [PR #5](https://github.com/weynne/taskflow-devsecops/pull/5) · [CI vermelho](https://github.com/weynne/taskflow-devsecops/actions/runs/39192182756) · [SAST vermelho](https://github.com/weynne/taskflow-devsecops/actions/runs/39192182787) |
| 3 | Merge recusado pela proteção da `main` enquanto os gates estavam vermelhos | [`docs/evidencias/demo-merge-bloqueado.txt`](docs/evidencias/demo-merge-bloqueado.txt) |
| 4 | O mesmo PR corrigido (revert), com os 7 checks verdes, e só então mergeado | [PR #5](https://github.com/weynne/taskflow-devsecops/pull/5) · [CI verde](https://github.com/weynne/taskflow-devsecops/actions/runs/39192311284) · [SAST verde](https://github.com/weynne/taskflow-devsecops/actions/runs/39192311400) |
| 5 | Trivy como gate da imagem + smoke test com runtime seguro no runner | [Container no PR #4](https://github.com/weynne/taskflow-devsecops/actions/runs/39192024740) (o artefato `container-reports` traz o relatório completo e o `docker history`) |
| 6 | Construção incremental por PR, um por etapa da esteira | [#1 CI](https://github.com/weynne/taskflow-devsecops/pull/1) · [#2 SAST](https://github.com/weynne/taskflow-devsecops/pull/2) · [#3 SCA](https://github.com/weynne/taskflow-devsecops/pull/3) · [#4 Container](https://github.com/weynne/taskflow-devsecops/pull/4) |

**Branch protection da `main`** (Settings → Branches): PR obrigatório; os 12 checks
(`Build e lint (ruff)`, `Testes (pytest)`, `SAST - Semgrep`, `Secret Scanning - Gitleaks`,
`SCA - pip-audit`, `SCA - Trivy fs`, `Imagem - build, Trivy e smoke test`,
`DAST - ZAP Baseline + XSS`, `IaC - Terraform validate`, `IaC - Checkov`,
`IaC - Trivy config`, `IaC - Politica do Compose`) obrigatórios, com
branch atualizada (`strict`); regras aplicadas também a administradores; force push e deleção
bloqueados; aprovação de 1 Code Owner exigida.

## Como rodar a aplicação localmente

Pré-requisitos: Python 3.12, Docker.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt

# Segredos SEMPRE em runtime, nunca no código.
export TASKFLOW_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
export ADMIN_PASSWORD="<escolha uma senha>"
export ALUNO_PASSWORD="<opcional>"

python app.py                    # http://127.0.0.1:5000 (usuário: admin)
```

O banco `taskflow.db` é criado na primeira execução. Para trocar as senhas iniciais, apague
o arquivo e rode de novo.

### Com Docker Compose (app + banco) e a stack de observabilidade

```bash
cp .env.example .env                                         # preencha; .env está no .gitignore
docker compose up --build -d                                 # web + db, ambos "healthy"
docker compose -f docker-compose.observability.yml up -d     # loki + promtail + grafana
# App: http://127.0.0.1:5000 · Grafana: http://127.0.0.1:3000 (dashboard "TaskFlow - Seguranca")

python3 scripts/simular-forca-bruta.py                       # gera o incidente do runbook
docker compose -f docker-compose.observability.yml down && docker compose down
```

### Com Docker (imagem endurecida + flags de runtime)

```bash
docker build -t taskflow:hardened .
cp .env.example .env            # preencha; .env está no .gitignore
./scripts/docker-run-seguro.sh  # --read-only, --cap-drop=ALL, no-new-privileges, UID 10001...
curl -i http://127.0.0.1:5000/login
docker stop taskflow-seguro
```

## Como rodar cada scanner localmente

```bash
# Lint + regras de segurança (flake8-bandit) e testes
ruff check .
python -m pytest -q

# SAST
pipx install semgrep==1.181.0      # ou: docker run --rm -v "$PWD:/src" -w /src semgrep/semgrep:1.181.0 semgrep scan ...
semgrep scan --config=p/python --config=p/flask --config=p/security-audit --metrics=off --error

# Secret scanning (histórico completo, com as regras e a allowlist do grupo)
gitleaks git . --config .gitleaks.toml --redact --verbose

# SCA (um arquivo por vez: requirements.txt tem hashes)
pip install pip-audit==2.10.1
pip-audit -r requirements.txt
pip-audit -r requirements-dev.txt
trivy fs --scanners vuln --severity HIGH,CRITICAL .

# Container
trivy config --severity HIGH,CRITICAL .
docker build -t taskflow:hardened .
trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 taskflow:hardened
docker history --no-trunc taskflow:hardened

# DAST (app precisa estar rodando, ex.: scripts/docker-run-seguro.sh com ALUNO_PASSWORD)
DAST_PASSWORD="<ALUNO_PASSWORD>" ./scripts/dast-scan.sh     # relatórios em reports/zap/

# IaC
(cd infra && terraform init -backend=false && terraform fmt -check && terraform validate)
pip install -r requirements-iac.txt
checkov -d . --framework terraform dockerfile github_actions --skip-path infra/.terraform --compact
trivy config --skip-dirs infra/.terraform .
python3 scripts/check-compose.py docker-compose.yml docker-compose.observability.yml

# Hardening do SO (diagnóstico)
git clone --depth 1 https://github.com/CISOfy/lynis.git && ./lynis/lynis audit system --quick
```

Para atualizar dependências: edite `requirements.in` e regenere o lock:

```bash
pip install pip-tools
pip-compile --generate-hashes --strip-extras --no-emit-index-url requirements.in
```

## Como disparar os workflows

- **Automático:** abrir ou atualizar um PR para a `main` dispara CI, SAST, SCA, Container,
  **DAST** e **IaC**. O merge na `main` (push) roda tudo de novo. Nenhum workflow tem filtro
  `paths:`. Todos os jobs são *required checks*, e um check obrigatório com `paths:` deixaria
  PRs que não tocam naqueles arquivos travados em "Expected — waiting for status"
  ([decisão detalhada](docs/iac.md#por-que-o-iac-scanyml-não-tem-filtro-paths)).
- **Manual:** aba **Actions** → escolha o workflow → **Run workflow** (todos têm
  `workflow_dispatch`). Pelo terminal: `gh workflow run dast.yml` / `gh workflow run iac-scan.yml`.
- **Agendado:** SCA diário (09:00 UTC); Container (10:00), DAST (11:00) e IaC (12:00) toda
  segunda-feira, para pegar CVEs e regras novas publicadas depois do último merge.

Configuração do repositório (branch protection, checks obrigatórios, CODEOWNERS, Dependabot):
[`docs/github-setup.md`](docs/github-setup.md).

## Decisões e riscos aceitos

| Decisão | Justificativa | Onde |
| --- | --- | --- |
| Trivy com `--ignore-unfixed` | 44 HIGH do Debian sem correção publicada: não há o que atualizar. Seguem no relatório (artefato) e são reavaliadas no scan semanal. | [`docs/hardening.md`](docs/hardening.md#risco-aceito-44-high-sem-correção) |
| Allowlist do Gitleaks | Só os 2 segredos didáticos da linha de base, condição `commit` **E** `valor`. Já removidos do código; valores públicos, nada a revogar. | [`.gitleaks.toml`](.gitleaks.toml) |
| Regras próprias no Gitleaks | As regras padrão não detectavam a `SECRET_KEY` de baixa entropia. | [`docs/sast-sca.md`](docs/sast-sca.md#2-gitleaks-histórico-completo-fetch-depth-0) |
| ruff `S` + Semgrep | O Semgrep OSS não pegou a SQLi da busca; o `S608` pega. | [`docs/sast-sca.md`](docs/sast-sca.md#falso-negativo-encontrado-decisão-técnica) |
| PyYAML e requests removidos | Não usados pela aplicação; dependência a menos, superfície a menos. | [`requirements.in`](requirements.in) |
| ~~Sem CSRF token nos formulários~~ | Resolvido na Atividade 2, depois que o ZAP apontou a falha (10202). | [`docs/dast.md`](docs/dast.md) |
| DAST = Baseline + varredura ativa **só de XSS** | O Baseline é passivo e não detecta XSS. O *full scan* seria mais lento e rodaria dezenas de regras irrelevantes. | [`docs/dast.md`](docs/dast.md#decisões-de-desenho) |
| Regras do ZAP: tudo FAIL por padrão | Regra não listada vira WARN, que não bloqueia; só 4 informativas foram rebaixadas, com justificativa. | [`.zap/rules.tsv`](.zap/rules.tsv) |
| 7 skips no Checkov e 2 ignores no Trivy | Justificados na linha (replicação, notificação, bucket de logs, SG anexado fora do escopo). Skip sem texto reprova o PR. | [`docs/iac.md`](docs/iac.md#skips-justificados) |
| Política própria para o Compose | Checkov e Trivy não analisam `docker-compose.yml`. | [`scripts/check-compose.py`](scripts/check-compose.py) |
| Promtail como root, **sem** `docker.sock` | Lê os logs do Docker (root `0640`) só leitura e sem capabilities; o socket equivaleria a root no host. | [`docs/observabilidade.md`](docs/observabilidade.md#arquitetura) |
| Promtail em vez do Grafana Alloy | Pedido do laboratório. O Promtail está em fim de vida (a Grafana recomenda o Alloy); a migração está no backlog. | — |
| Sem rate limit no login | Mantido de propósito para a simulação; é a ação nº 1 do pós-incidente. | [runbook](docs/runbook-login-bruteforce.md#fase-4--atividade-pós-incidente) |
| Banco PostgreSQL "simulado" | Como no laboratório: o `db` existe para exercitar o isolamento de rede; a app segue em SQLite. | [`docker-compose.yml`](docker-compose.yml) |

Nenhuma supressão `# nosemgrep`, `--exit-zero`, `continue-on-error` ou `soft_fail` é usada.

## Material da disciplina (Atividade 2)

O repositório `aula_graduacao_devsecops` não estava acessível ao grupo durante a
implementação. `dast.yml`, `iac-scan.yml`, o Compose seguro, o Terraform corrigido, a
instrumentação da app e a stack de observabilidade foram escritos a partir dos slides das
aulas 5 e 6 e do enunciado. As versões inseguras usadas como "antes" (o
`docker-compose.insecure.yml` e o `main.insecure.tf`, com as falhas descritas nos slides)
foram reconstruídas só para gerar as evidências, e não ficam no repositório para não
reprovar os próprios gates.

## Reaproveitamento do material da disciplina

Adaptado de `codigo/` do repositório da disciplina: `ci-basico.yml`, `sast.yml` e `sca.yml`
(viraram `ci.yml`, `sast.yml` e `sca.yml`, com actions pinadas, `permissions` mínimas,
Gitleaks via binário verificado e Trivy fs); `Dockerfile.hardened` (com digest,
`--require-hashes`, código somente leitura, healthcheck); `docker-run-seguro.sh` (segredos
via `--env-file`/`-e NOME`, `--pids-limit`, porta só local, reutilizado no smoke test do CI);
`dependabot.yml` (+ ecossistema docker). O `requirements-fixed.txt` **não** foi usado: as
versões dele já tinham CVEs ([detalhes](docs/sast-sca.md#3-pip-audit)).

## Estrutura

```text
.
├── app.py, wsgi.py, templates/   # aplicação corrigida (gunicorn usa wsgi.py)
├── static/style.css              # único estilo (a CSP proíbe estilo inline)
├── tests/                        # testes de regressão de segurança
├── requirements.in / .txt        # dependências diretas / lock com hashes
├── requirements-dev.txt          # ruff, pytest
├── Dockerfile, .dockerignore     # imagem endurecida
├── scripts/
│   ├── docker-run-seguro.sh      # execução com flags de runtime seguras
│   ├── dast-scan.sh              # DAST: espera ativa, login, ZAP Baseline + XSS (CI e local)
│   ├── check-compose.py          # gate de política dos arquivos Compose
│   └── simular-forca-bruta.py    # simulação do incidente (só localhost)
├── .zap/ rules.tsv xss-active.yaml   # regras do Baseline e plano da varredura de XSS
├── docker-compose.yml            # app + banco, seguro (redes, read-only, limites...)
├── docker-compose.observability.yml  # loki + promtail + grafana
├── observability/                # configs do Loki/Promtail e provisioning do Grafana
├── infra/                        # Terraform (AWS) corrigido + lock file
├── requirements-iac.txt          # Checkov (versão fixa)
├── .gitleaks.toml, .trivyignore  # configuração e exceções justificadas dos scanners
├── .github/
│   ├── workflows/ ci.yml sast.yml sca.yml container.yml dast.yml iac-scan.yml
│   ├── actions/setup-python-deps/
│   ├── dependabot.yml
│   └── CODEOWNERS
└── docs/ hardening.md sast-sca.md dast.md iac.md observabilidade.md
          runbook-login-bruteforce.md github-setup.md apresentacao*.md evidencias/
```
