# SAST, secret scanning e SCA: antes × depois

Medições de 18/10/2026: Semgrep 1.181.0, Gitleaks 8.30.1, pip-audit 2.10.1.

## 1. Semgrep (`p/python`, `p/flask`, `p/security-audit`, `--error`)

```bash
semgrep scan --config=p/python --config=p/flask --config=p/security-audit --metrics=off --error
```

| Antes (linha de base) | Depois |
| --- | --- |
| **10 findings bloqueantes** ([evidência](evidencias/semgrep-antes.txt)) | **0 findings, 0 supressões** ([evidência](evidencias/semgrep-depois.txt)) |

| Regra disparada na linha de base | Linha | Correção |
| --- | --- | --- |
| `avoid_hardcoded_config_SECRET_KEY` | 28 | `SECRET_KEY` lida de `TASKFLOW_SECRET_KEY`; a app não sobe sem ela |
| `tainted-sql-string` (login) | 101 | consulta parametrizada `WHERE username = ?` |
| `raw-html-format` / `raw-html-concat` / `directly-returned-format-string` (×6) | 163, 170 | HTML movido para templates Jinja2 com autoescape (XSS armazenado) |
| `avoid_app_run_with_bad_host` | 227 | bind padrão `127.0.0.1`; em produção quem faz o bind é o gunicorn |
| `debug-enabled` | 227 | `debug=True` removido |

### Falso negativo encontrado (decisão técnica)

O Semgrep OSS **não** acusou a SQL Injection da **busca** de tarefas
(`"... AND title LIKE '%" + search + "%'"`): a regra de taint do OSS não acompanhou esse
fluxo. Duas consequências:

1. O grupo corrigiu a busca mesmo assim (parametrizada, `LIKE ?` com `f"%{search}%"`).
2. O `ruff` com as regras **flake8-bandit (`S`)** foi adicionado ao job de lint. A regra
   `S608` detecta as **duas** concatenações de SQL, então a esteira tem duas camadas de
   SAST que se complementam.

Os testes `tests/test_security.py` fixam o comportamento corrigido (SQLi no login e na
busca, XSS escapado, senha com hash, `/debug/info` → 404, cookie `HttpOnly`) e rodam a
cada PR.

### Correções além do mínimo pedido

- `/debug/info` (devolvia a `SECRET_KEY` sem autenticação) **removido**.
- XSS armazenado corrigido com templates (o material deixava para o Módulo 4).
- `session.clear()` no login (evita session fixation), cookie `HttpOnly` + `SameSite=Lax`.
- Senhas iniciais saíram do código: `ADMIN_PASSWORD` (obrigatória) e `ALUNO_PASSWORD`
  (opcional) vêm do ambiente, e o banco guarda só o hash (`werkzeug.security`, scrypt com salt).

## 2. Gitleaks (histórico completo, `fetch-depth: 0`)

```bash
gitleaks git . --config .gitleaks.toml --redact --verbose
```

**Achado da análise:** com as regras padrão, o Gitleaks **não** detectou nenhum dos dois
segredos da linha de base. A `SECRET_KEY` e o `ADMIN_PASSWORD` didáticos têm baixa
entropia, então as regras genéricas os descartam.

Decisão do grupo (`.gitleaks.toml`):

1. **Manter todas as regras padrão** (`[extend] useDefault = true`).
2. **Criar duas regras do projeto:**
   - `flask-secret-key-hardcoded`: `SECRET_KEY` recebendo uma string literal;
   - `dockerfile-env-secret`: `ENV`/`ARG` com `PASSWORD|SECRET|TOKEN|API_KEY` em Dockerfile.

   Com elas, o scan do histórico passa a acusar os **2** segredos da linha de base.
3. **Allowlist específica** para esses 2 achados. As duas condições valem juntas (`AND`):
   o achado precisa estar **no commit da linha de base** e ter **exatamente** um dos dois
   valores didáticos. Qualquer segredo novo, em qualquer outro commit, continua quebrando
   o pipeline. Não há credencial a revogar: os valores são públicos (vêm do material da
   disciplina) e já saíram do código atual.

| | Achados |
| --- | --- |
| Regras padrão | 0 (falso negativo) |
| Regras padrão + regras do projeto, sem allowlist | 2 (`app.py:28`, `Dockerfile:23`, commit da linha de base) |
| Configuração final (com allowlist) | 0 |

**Falso positivo triado:** ao versionar `docs/evidencias/docker-history-depois.txt`, a regra
padrão `generic-api-key` acusou `ENV GPG_KEY=7169605F…6305`. É o **fingerprint público** da
chave GPG do release manager do Python, gravado pela imagem oficial `python:3.12-slim` para
verificar o tarball do Python. Não é credencial. A segunda allowlist do `.gitleaks.toml` libera
apenas esse valor exato, e apenas em `docs/evidencias/`.

## 3. pip-audit

```bash
pip-audit -r requirements.txt
pip-audit -r requirements-dev.txt
```

| Antes | Depois |
| --- | --- |
| **Flask 0.12.2, Jinja2 2.11.3, Werkzeug 0.15.4, PyYAML 5.1, requests 2.6.0**: 27 advisories distintos ([evidência](evidencias/pip-audit-antes.txt)) | **No known vulnerabilities found** nos dois arquivos ([evidência](evidencias/pip-audit-depois.txt)) |

Decisões:

- **Versões do material de referência já estavam vulneráveis.** O
  `codigo/sast/requirements-fixed.txt` da disciplina usa Werkzeug 3.0.6, Flask 3.0.3 e
  Jinja2 3.1.4, que hoje têm advisories (`PYSEC-2026-2046`, `-2044`, `-2320` e `-4312`;
  `PYSEC-2026-2151`; `PYSEC-2026-1475`/`-1471`). Usamos as versões corrigidas atuais:
  **Flask 3.1.3, Werkzeug 3.1.9, Jinja2 3.1.6, gunicorn 26.2.0**. É o aviso do slide
  ("verifique a versão mais recente no momento") acontecendo de verdade.
- **PyYAML e requests foram removidos:** a aplicação não os usa. Dependência a menos é
  superfície de ataque a menos.
- **Árvore completa travada com hashes:** `requirements.in` lista as diretas e o
  `pip-compile --generate-hashes` gera o `requirements.txt` com todas as transitivas
  (blinker, click, itsdangerous, markupsafe) e seus sha256. A imagem instala com
  `--require-hashes`.
- **Segunda camada:** `trivy fs` roda no mesmo workflow (outras fontes de advisories).
- **Monitoramento contínuo:** o `sca.yml` roda **diariamente** (`schedule`), e o
  Dependabot abre PRs semanais para `pip`, `github-actions` e `docker`.
