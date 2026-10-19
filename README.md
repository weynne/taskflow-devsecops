# TaskFlow DevSecOps — Esteira Segura

Atividade 1 da disciplina DevSecOps (CESAR School). A aplicação **TaskFlow** (Flask),
importada propositalmente vulnerável do `app-exemplo/` da disciplina, protegida por uma
esteira de CI no GitHub Actions. A esteira **bloqueia o merge na `main`** quando build,
lint, testes, SAST, secret scanning, SCA ou o scan da imagem encontram problemas.

Grupo **WJD** (o mesmo da disciplina de CI/CD,
[`cicd-grupo-WJD`](https://github.com/weynne/cicd-grupo-WJD)):

| Membro | GitHub | Frente principal |
| --- | --- | --- |
| Weynne Guimarães | [@weynne](https://github.com/weynne) | Dono do repositório: esteira de CI, branch protection, workflow de container |
| Jéssica Camarço | [@jessicacamarco](https://github.com/jessicacamarco) | SAST e secret scanning: Semgrep, Gitleaks, correções no `app.py` e testes |
| Diego Tavares | [@diegotavares16](https://github.com/diegotavares16) | SCA e hardening: pip-audit, Dependabot, Dockerfile, Trivy e Lynis |

Os donos de cada área estão em [`.github/CODEOWNERS`](.github/CODEOWNERS): cada área tem
o mantenedor ao lado do dono do repositório, e toda regra tem no mínimo dois donos.

## Visão geral da esteira

```text
PR para main ──┬── CI ────────── Build e lint (ruff + flake8-bandit)
               │                 Testes (pytest: regressão de segurança)
               ├── SAST ──────── SAST - Semgrep (p/python, p/flask, p/security-audit)
               │                 Secret Scanning - Gitleaks (histórico completo)
               ├── SCA ───────── SCA - pip-audit (gate)   SCA - Trivy fs (2ª camada)
               └── Container ─── Trivy config (Dockerfile) → build → Trivy image
                                 → sem segredo no docker history → smoke test com runtime seguro
                         │
          todos verdes + 1 aprovação do CODEOWNER ──► merge liberado
```

| Workflow | Gatilhos | O que bloqueia |
| --- | --- | --- |
| [`ci.yml`](.github/workflows/ci.yml) | PR → main, push na main, manual | erro de sintaxe, lint/`S608` (SQL concatenado), `S105` (senha hardcoded), teste de segurança falhando |
| [`sast.yml`](.github/workflows/sast.yml) | PR → main, push na main, manual | qualquer finding do Semgrep (`--error`); qualquer segredo no histórico (Gitleaks) |
| [`sca.yml`](.github/workflows/sca.yml) | PR → main, push na main, **diário**, manual | qualquer CVE conhecida nas dependências (pip-audit); HIGH/CRITICAL no Trivy fs |
| [`container.yml`](.github/workflows/container.yml) | PR → main, push na main, **semanal**, manual | misconfig HIGH/CRITICAL no Dockerfile; CVE HIGH/CRITICAL **com correção** na imagem; segredo em camada; container que não sobe com `--read-only`/`--cap-drop=ALL` |
| [`dependabot.yml`](.github/dependabot.yml) | semanal (GitHub) | abre PRs para pip, GitHub Actions e imagem Docker |

Boas práticas aplicadas em todos os workflows: `permissions: contents: read` (mínimo);
actions **pinadas por SHA** com a versão em comentário; ferramentas com versão fixa
(Semgrep, pip-audit, ruff) e imagem do Trivy por **digest**; Gitleaks baixado do release
oficial com **checksum sha256 verificado**; `persist-credentials: false` no checkout;
versões e severidades de corte parametrizadas em `env:`; setup do Python reutilizado via
action composta ([`.github/actions/setup-python-deps`](.github/actions/setup-python-deps/action.yml)),
com a versão vinda do arquivo [`.python-version`](.python-version) (fonte única).

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

Detalhes e evidências de antes × depois: [`docs/sast-sca.md`](docs/sast-sca.md) e
[`docs/hardening.md`](docs/hardening.md).

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

# Hardening do SO (diagnóstico)
git clone --depth 1 https://github.com/CISOfy/lynis.git && ./lynis/lynis audit system --quick
```

Para atualizar dependências: edite `requirements.in` e regenere o lock:

```bash
pip install pip-tools
pip-compile --generate-hashes --strip-extras --no-emit-index-url requirements.in
```

## Como disparar os workflows

- **Automático:** abrir ou atualizar um PR para a `main` dispara CI, SAST, SCA e Container.
  O merge na `main` (push) roda tudo de novo.
- **Manual:** aba **Actions** → escolha o workflow → **Run workflow** (todos têm `workflow_dispatch`).
- **Agendado:** SCA diário (09:00 UTC) e Container semanal (segunda, 10:00 UTC), para pegar
  CVEs publicadas depois do último merge.

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
| Sem CSRF token nos formulários | Fora do escopo dos scanners desta atividade; será tratado com o DAST (Atividade 2). | — |

Nenhuma supressão `# nosemgrep`, `--exit-zero`, `continue-on-error` ou `soft_fail` é usada.

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
├── tests/                        # testes de regressão de segurança
├── requirements.in / .txt        # dependências diretas / lock com hashes
├── requirements-dev.txt          # ruff, pytest
├── Dockerfile, .dockerignore     # imagem endurecida
├── scripts/docker-run-seguro.sh  # execução com flags de runtime seguras
├── .gitleaks.toml, .trivyignore  # configuração e exceções justificadas dos scanners
├── .github/
│   ├── workflows/ ci.yml sast.yml sca.yml container.yml
│   ├── actions/setup-python-deps/
│   ├── dependabot.yml
│   └── CODEOWNERS
└── docs/ hardening.md sast-sca.md github-setup.md apresentacao.md evidencias/
```
