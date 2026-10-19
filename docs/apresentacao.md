# Roteiro da apresentação (~10 min)

Mostrar repositório, PRs e aba Actions, não slides. Os slides só servem de guia, e os links
deles abrem direto no GitHub. Uma pessoa conduz a apresentação, e os demais membros do grupo
podem complementar durante a fala.

| # | Bloco | O que mostrar |
| --- | --- | --- |
| 1 | Contexto e matriz de responsabilidades | grupo WJD e as áreas do [`CODEOWNERS`](../.github/CODEOWNERS) |
| 2 | A esteira | aba **Actions** (4 workflows verdes na `main`) e **Settings → Branches** (7 checks obrigatórios) |
| 3 | Demo ao vivo do shift-left | PR com falha → gate vermelho → merge bloqueado → correção → verde (abaixo) |
| 4 | Antes × depois | números do Trivy, Semgrep, Gitleaks e pip-audit (abaixo) |
| 5 | Decisões técnicas | uma ou duas da lista abaixo |
| 6 | Aprendizado mais impactante | ver o fim deste arquivo |

## Matriz de responsabilidades (CODEOWNERS)

| Code owner | Área | Caminhos |
| --- | --- | --- |
| Weynne Guimarães ([@weynne](https://github.com/weynne)) | Dono do repositório e da esteira | todo o repositório, `/.github/` |
| Jéssica Camarço ([@jessicacamarco](https://github.com/jessicacamarco)) | Aplicação, SAST e secret scanning | `app.py`, `wsgi.py`, `templates/`, `tests/`, `.gitleaks.toml`, `/.github/` |
| Diego Tavares ([@diegotavares16](https://github.com/diegotavares16)) | Dependências e container | `requirements.*`, `Dockerfile`, `.dockerignore`, `.trivyignore`, `scripts/` |

Toda regra tem dois donos, então quem abre o PR nunca é o único revisor possível.

## Demo do shift-left (preparar a branch ANTES da aula)

O mesmo ciclo já está registrado no [PR #5](https://github.com/weynne/taskflow-devsecops/pull/5):
use-o como referência e como plano B. Ao vivo, usa-se uma branch nova.

1. Criar a branch com a falha (reintroduz uma SQL Injection no login):

   ```bash
   git switch main && git pull
   git switch -c demo/sqli-ao-vivo
   python3 - <<'PY'
   from pathlib import Path
   p = Path("app.py"); s = p.read_text()
   s = s.replace(
       'cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))',
       'cur = db.execute(f"SELECT * FROM users WHERE username = \'{username}\'")',
   )
   p.write_text(s)
   PY
   git commit -am "feat: simplifica consulta de usuario no login"
   git push -u origin demo/sqli-ao-vivo
   ```

2. Abrir o PR para a `main` e mostrar ao vivo:
   - `SAST - Semgrep` vermelho: `python.flask.security.injection.tainted-sql-string`;
   - `Build e lint (ruff)` vermelho: `S608 Possible SQL injection vector`;
   - o botão **Merge** bloqueado ("Required statuses must pass").
   - Ponto para comentar: `Testes (pytest)` continua **verde**. O bypass `admin' --` não
     funciona porque a senha é conferida depois por `check_password_hash`. Isso é defesa em
     profundidade, mas a query continua injetável (dá para extrair dados com `UNION`), e
     por isso o SAST bloqueia.

3. Corrigir com um **novo commit** (sem force push, para o histórico mostrar o ciclo):

   ```bash
   git revert --no-edit HEAD
   git push
   ```

   Os checks ficam verdes, mas o merge **continua bloqueado** até um Code Owner aprovar
   (fase 2 da branch protection, ligada antes da entrega). Como o autor não pode aprovar o
   próprio PR, combine antes com outro Code Owner (Jéssica ou Diego) para aprovar no momento
   da demo: gate automático e revisão humana, os dois em sequência.

   Antes da aula, confira em **Settings → Branches** que "Require approvals" e
   "Require review from Code Owners" estão marcados (ver [github-setup.md](github-setup.md#fase-2--entrega-depois-do-pr-5-antes-de-enviar-ao-professor)).

Plano B, se a internet falhar: mostrar o [PR #5](https://github.com/weynne/taskflow-devsecops/pull/5)
já registrado, a saída em [`evidencias/demo-merge-bloqueado.txt`](evidencias/demo-merge-bloqueado.txt)
ou rodar localmente `semgrep scan --config=p/flask --error` na branch da demo.

## Antes × depois (números para citar)

| Ferramenta | Antes | Depois |
| --- | --- | --- |
| Semgrep | 10 findings bloqueantes | 0, sem supressões |
| Gitleaks | 0 com as regras padrão (falso negativo) → 2 com as regras do grupo | 0 (allowlist só da linha de base) |
| pip-audit | 27 advisories em 5 pacotes | 0 |
| Trivy — CRITICAL | 17 | 0 |
| Trivy — HIGH | 357 (+14 em libs Python) | 44, todas sem correção publicada (risco aceito) |
| Imagem | 1,66 GB, root, `ADMIN_PASSWORD` no `docker history` | 188 MB, UID 10001, sem segredo |

## Decisões técnicas (escolher 1 ou 2)

1. **`--ignore-unfixed` no Trivy**: 44 HIGH sem correção no Debian não bloqueiam, mas
   aparecem no relatório e são reavaliadas no scan semanal ([hardening.md](hardening.md)).
2. **Regras próprias no Gitleaks**: as regras padrão não pegavam a `SECRET_KEY` didática.
   Criamos regras do projeto e uma allowlist restrita ao commit e ao valor da linha de base
   ([sast-sca.md](sast-sca.md)).
3. **Falso negativo do Semgrep** na busca: corrigido mesmo assim, e o `ruff` com flake8-bandit
   virou a segunda camada de SAST.
4. **O material de referência já estava desatualizado**: Werkzeug 3.0.6 tinha CVEs novas,
   então fomos para 3.1.9 e travamos a árvore inteira com hashes.

## Aprendizados para fechar (escolher um)

- Sem *required checks*, o pipeline vermelho é só decoração: o gate é a configuração da `main`,
  não o YAML.
- Scanner também erra para os dois lados: falso negativo no Semgrep e no Gitleaks, falso
  positivo no fingerprint GPG. Verde só vale se for honesto.
- "Corrigido hoje" expira: a versão segura do material de referência já tinha CVE meses
  depois. Por isso SCA agendado + Dependabot.
