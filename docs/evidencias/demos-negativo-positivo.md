# Demos dos gates da Atividade 2: negativo × positivo

Cada demo é um PR com dois commits, enviados **em pushes separados**: primeiro o commit
que reabre a falha (os checks ficam vermelhos e o merge é bloqueado), depois o revert (os
checks voltam a ficar verdes). Os PRs ficam abertos/fechados **sem merge**, como registro.
Executado em 28/10/2026.

## DAST: XSS reaberto com `| safe` ([PR #20](https://github.com/weynne/taskflow-devsecops/pull/20))

| | Negativo: `41ca4fb` (`\| safe` na descrição) | Positivo: `9f9b1a3` (revert) |
| --- | --- | --- |
| `DAST - ZAP Baseline + XSS` | ❌ [run](https://github.com/weynne/taskflow-devsecops/actions/runs/40798277508) | ✅ [run](https://github.com/weynne/taskflow-devsecops/actions/runs/40798549203) |
| `Testes (pytest)` | ❌ [run](https://github.com/weynne/taskflow-devsecops/actions/runs/40798277636) | ✅ [run](https://github.com/weynne/taskflow-devsecops/actions/runs/40798549066) |
| `SAST - Semgrep` | ❌ [run](https://github.com/weynne/taskflow-devsecops/actions/runs/40798277453) | ✅ [run](https://github.com/weynne/taskflow-devsecops/actions/runs/40798549167) |
| Demais checks | ✅ | ✅ (12/12) |
| Merge | **bloqueado** pelos checks | bloqueado só pela revisão de Code Owner |

Trechos dos logs do negativo:

```text
# DAST (scripts/dast-scan.sh)
==> 4/4 ZAP varredura ativa de XSS (gate: risco >= Medium)
::error::ZAP confirmou XSS:
Cross Site Scripting (Persistent) [High (Medium)] em http://127.0.0.1:5000/tasks
Cross Site Scripting (Reflected) [High (Medium)] em http://127.0.0.1:5000/tasks/new

# pytest
FAILED tests/test_security.py::test_xss_armazenado_e_escapado
FAILED tests/test_security.py::test_templates_nao_desligam_o_autoescape
2 failed, 15 passed

# Semgrep (camada extra, já existia desde a Atividade 1)
templates/tasks.html
  python.flask.security.xss.audit.template-unescaped-with-safe   ❰❰ Blocking ❱❱
```

Três camadas independentes pegaram a mesma regressão: DAST (app em execução), teste de
regressão e SAST.

## IaC: bucket público e banco exposto ([PR #21](https://github.com/weynne/taskflow-devsecops/pull/21))

| | Negativo: `2da8fd1` (`restrict_public_buckets = false` + `5432:5432` no db) | Positivo: `24c0d4f` (revert) |
| --- | --- | --- |
| `IaC - Checkov` | ❌ [run](https://github.com/weynne/taskflow-devsecops/actions/runs/40798282423) | ✅ [run](https://github.com/weynne/taskflow-devsecops/actions/runs/40798549010) |
| `IaC - Trivy config` | ❌ (mesmo run) | ✅ (mesmo run) |
| `IaC - Politica do Compose` | ❌ (mesmo run) | ✅ (mesmo run) |
| `Imagem - build, Trivy e smoke test` | ❌ [run](https://github.com/weynne/taskflow-devsecops/actions/runs/40798282337) | ✅ [run](https://github.com/weynne/taskflow-devsecops/actions/runs/40798548990) |
| Demais checks | ✅ | ✅ (12/12) |
| Merge | **bloqueado** pelos checks | bloqueado só pela revisão de Code Owner |

Trechos dos logs do negativo:

```text
# Checkov
Check: CKV_AWS_56: "Ensure S3 bucket has 'restrict_public_buckets' enabled"
	FAILED for resource: aws_s3_bucket_public_access_block.relatorios

# Trivy config
Failures: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)
AWS-0093 (HIGH): Public access block does not restrict public buckets

# Politica do Compose (scripts/check-compose.py)
  FAIL     db         porta-loopback       esperado: portas publicadas apenas em 127.0.0.1
  FAIL     db         banco-sem-porta      esperado: banco sem porta publicada no host
2 falha(s) de politica.
```

O `Imagem - build, Trivy e smoke test` também reprovou porque o Trivy config desse
workflow varre o repositório inteiro, inclusive `infra/`.

## Positivo da esteira completa

- [PR #14](https://github.com/weynne/taskflow-devsecops/pull/14) (Atividade 2): 12/12 checks verdes antes do merge.
- `main` após o merge (`42bf7c9`): [CI](https://github.com/weynne/taskflow-devsecops/actions/runs/40798180305) ·
  [SAST](https://github.com/weynne/taskflow-devsecops/actions/runs/40798180322) · [SCA](https://github.com/weynne/taskflow-devsecops/actions/runs/40798180245) ·
  [Container](https://github.com/weynne/taskflow-devsecops/actions/runs/40798180152) · [DAST](https://github.com/weynne/taskflow-devsecops/actions/runs/40798180258) ·
  [IaC](https://github.com/weynne/taskflow-devsecops/actions/runs/40798180131)
