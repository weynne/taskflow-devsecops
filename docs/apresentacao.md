# Roteiro da apresentação (~10 min)

Mostrar repositório, PRs e aba Actions, não slides.

| Tempo | Bloco | Quem |
| --- | --- | --- |
| 0:00–1:00 | Contexto: grupo, membros e papéis | Weynne |
| 1:00–5:00 | Demo ao vivo do shift-left (abaixo) | Jéssica |
| 5:00–7:00 | Antes × depois (Trivy, Semgrep, pip-audit) | Diego |
| 7:00–9:00 | Decisões técnicas | Jéssica (Gitleaks/Semgrep) e Diego (Trivy) |
| 9:00–10:00 | Aprendizado mais impactante | todos |

## Demo do shift-left (preparar a branch ANTES da aula)

1. Criar a branch com a falha (reintroduz uma SQL Injection no login):

   ```bash
   git switch main && git pull
   git switch -c demo/shift-left-sqli
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
   git push -u origin demo/shift-left-sqli
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

   Os checks ficam verdes, mas o merge **continua bloqueado** até um CODEOWNER aprovar
   (fase 2 da branch protection, ligada antes da entrega). Jéssica ou Diego aprovam ao vivo,
   e o merge é liberado: gate automático e revisão humana, os dois em sequência.

   Antes da aula, confira em **Settings → Branches** que "Require approvals" e
   "Require review from Code Owners" estão marcados (ver [github-setup.md](github-setup.md#fase-2--entrega-depois-do-pr-5-antes-de-enviar-ao-professor)).

Plano B, se a internet falhar: rodar localmente `semgrep scan --config=p/flask --error`
e `pytest` na branch da demo.

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
