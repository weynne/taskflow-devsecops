# DAST — OWASP ZAP no pipeline (Módulo 4)

O workflow [`dast.yml`](../.github/workflows/dast.yml) sobe a TaskFlow **dentro do runner**
e a ataca com o OWASP ZAP. Ele roda em todo PR para a `main`, a cada push na `main`, toda
segunda-feira e sob demanda. O check `DAST - ZAP Baseline + XSS` é obrigatório na branch
protection.

## Como o job funciona

```text
docker build (Dockerfile de produção)
   └─ docker-run-seguro.sh: --read-only, --cap-drop=ALL, no-new-privileges, UID 10001,
      segredos efêmeros gerados no run (TASKFLOW_SECRET_KEY, ADMIN_PASSWORD, ALUNO_PASSWORD)
        └─ scripts/dast-scan.sh
             1. espera ativa: curl em /login até ver "TaskFlow - Login" (60 s, senão FALHA)
             2. login real como "aluno" (com token CSRF); falha se /tasks não abrir
             3. ZAP Baseline autenticado ── gate: .zap/rules.tsv
             4. ZAP varredura ATIVA só de XSS ── gate: qualquer XSS >= Medium
        └─ relatórios HTML/MD/JSON publicados como artefato "zap-reports" (if: always())
```

O mesmo script roda localmente, e por isso serve de plano B da demo:

```bash
docker build -t taskflow:hardened .
cp .env.example .env              # preencha, inclusive ALUNO_PASSWORD
./scripts/docker-run-seguro.sh
DAST_PASSWORD="<ALUNO_PASSWORD do .env>" ./scripts/dast-scan.sh   # relatórios em reports/zap/
```

### Decisões de desenho

| Decisão | Por quê |
| --- | --- |
| **Espera ativa** pelo `/login` (não `sleep`) + mínimo de URLs no spider | Evita o "ZAP atacando o nada": se a app não subiu, ou se o spider não passou do login, o job **falha** em vez de gerar um relatório falsamente limpo. |
| **Scan autenticado** (cookie de sessão injetado pelo Replacer do ZAP) | Sem login, o spider só enxerga `/login`. A sessão do Flask é assinada e não tem estado no servidor, então o mesmo cookie vale o scan inteiro. O cookie já leva o token CSRF, e por isso os POSTs do ZAP passam pela validação e testam o fluxo real. |
| **Baseline + varredura ativa só de XSS** | O Baseline é **passivo** e não tem nenhuma regra que prove XSS. Para o gate bloquear um PR que reabre o XSS, o [plano do Automation Framework](../.zap/xss-active.yaml) injeta payloads apenas com as 4 regras de XSS (40012, 40014, 40016, 40017). O alvo é a instância efêmera do próprio job, nunca um ambiente real. Custo: ~1 min. |
| **Toda regra passiva começa em FAIL** | O `zap-baseline.py` trata regra não listada como WARN, que não bloqueia. O [`rules.tsv`](../.zap/rules.tsv) lista **as 67 regras** da versão fixada, todas em FAIL; só as rebaixadas abaixo têm outra ação. |
| Sem `continue-on-error`; `-I` só para WARN | O exit code do script é o gate. `-I` impede apenas que WARN (rebaixado e justificado) quebre o job; FAIL e erro do ZAP quebram. |
| Imagem do ZAP fixada por **digest** (2.17.0) | O `rules.tsv` foi gerado nessa versão (`zap-baseline.py -g`). Uma versão nova pode trazer regras novas; a atualização é manual e regera a lista. |

### Regras rebaixadas no `rules.tsv`

Todas são **informativas**: não descrevem vulnerabilidade. A justificativa está na própria
linha do arquivo.

| Regra | Ação | Justificativa |
| --- | --- | --- |
| 10031 User Controllable HTML Element Attribute (Potential XSS) | WARN | O ZAP só vê o `q` refletido no atributo `value`. O autoescape o escapa, como provam a varredura ativa de XSS e `test_xss_refletido_no_parametro_q_e_escapado`. Continua visível no relatório. |
| 10049 Non-Storable Content | IGNORE | Registra que as respostas não vão para cache. É o comportamento desejado (`Cache-Control: no-store`). |
| 10111 Authentication Request Identified | IGNORE | Apenas identifica o formulário de login. |
| 10112 Session Management Response Identified | IGNORE | Apenas identifica o cookie de sessão; as flags do cookie seguem cobertas por 10010, 10054 e 90033 (FAIL). |

## Correções na aplicação

| Item | Antes | Depois | Teste de regressão |
| --- | --- | --- | --- |
| XSS armazenado (descrição) | HTML montado com f-string | templates Jinja2 com autoescape, **sem `\| safe`** | `test_xss_armazenado_e_escapado`, `test_templates_nao_desligam_o_autoescape` |
| XSS no parâmetro `q` da busca (Encontro 9) | refletido cru | `value="{{ search }}"` escapado (inclusive aspas) | `test_xss_refletido_no_parametro_q_e_escapado` |
| XSS na mensagem de erro do login (Encontro 9) | refletida crua | `{{ error }}` escapado; a mensagem é fixa e não ecoa o username (também evita enumeração de usuários) | `test_login_com_senha_errada_falha` |
| `/debug/info` | devolvia `SECRET_KEY` e versões | rota removida (404) | `test_endpoint_de_debug_removido` + smoke test do `container.yml` |
| `debug=True` | Werkzeug debugger exposto | `TASKFLOW_DEBUG=1` liga explicitamente; **desligado por padrão**; a imagem usa gunicorn | `test_debug_desligado_por_padrao` |
| Cabeçalhos de segurança | nenhum | CSP (`default-src 'none'`, sem script), `X-Frame-Options: DENY`, `nosniff`, `Permissions-Policy`, COOP/COEP/CORP, `Referrer-Policy`, `Cache-Control: no-store` | `test_cabecalhos_de_seguranca_presentes` |
| Anti-CSRF | formulários sem token | token por sessão em todo formulário, validado em todo POST com `compare_digest` | `test_post_sem_token_csrf_e_rejeitado`, `test_login_sem_token_csrf_e_rejeitado` |

A CSP bloqueia estilo inline, então o único estilo da página foi para
[`static/style.css`](../static/style.css).

## Achados antes × depois, mapeados ao OWASP Top 10 2025

Executado com [`scripts/dast-scan.sh`](../scripts/dast-scan.sh) contra três versões da
aplicação:

- **Original:** a linha de base vulnerável do `app-exemplo/`, commit `299955b`.
- **Atividade 1:** a `main` antes desta entrega.
- **Atividade 2:** esta branch.

Saídas completas em [`docs/evidencias/zap-*.txt`](evidencias/).

| Alerta do ZAP (id) | Risco | OWASP Top 10 2025 | Original | Atividade 1 | Atividade 2 |
| --- | --- | --- | :---: | :---: | :---: |
| Cross Site Scripting (Persistent) (40014) em `/tasks` | High | **A05 Injection** | ❌ | ✅ | ✅ |
| Cross Site Scripting (Reflected) (40012) em `/tasks/new` | High | **A05 Injection** | ❌ | ✅ | ✅ |
| Content Security Policy Header Not Set (10038) | Medium | **A02 Security Misconfiguration** | ❌ | ❌ | ✅ |
| Missing Anti-clickjacking Header (10020) | Medium | **A02 Security Misconfiguration** | ❌ | ❌ | ✅ |
| Absence of Anti-CSRF Tokens (10202) | Medium | **A01 Broken Access Control** | ¹ | ❌ | ✅ |
| X-Content-Type-Options Header Missing (10021) | Low | **A02 Security Misconfiguration** | ❌ | ❌ | ✅ |
| Permissions Policy Header Not Set (10063) | Low | **A02 Security Misconfiguration** | ❌ | ❌ | ✅ |
| Insufficient Site Isolation Against Spectre / COEP (90004) | Low | **A02 Security Misconfiguration** | ❌ | ❌ | ✅ |
| Server Leaks Version Information: `Werkzeug/0.15.4 Python/3.7` (10036) | Low | **A02 Security Misconfiguration** (versão vulnerável exposta também alimenta **A03 Software Supply Chain Failures**) | ❌ | ✅ | ✅ |
| `/debug/info` + Werkzeug debugger com traceback (fora do spider; verificado no smoke test) | High | **A02 Security Misconfiguration** e **A10 Mishandling of Exceptional Conditions** | ❌ | ✅ | ✅ |
| **Resultado do gate** | | | **reprovado** (6 FAIL + 2 XSS) | **reprovado** (6 FAIL) | **aprovado** (0 FAIL, 0 XSS) |

¹ **Falso negativo do ZAP.** Na versão original o spider visitou `/tasks/new` e a regra
10202 saiu como PASS, embora o formulário não tivesse token. Uma diferença visível é que a
versão original devolve fragmentos de HTML, sem `<html>`/`<body>`, montados com f-string.
A ausência de token era real e foi apontada no scan da Atividade 1, que já usa templates. É
mais um motivo para não tratar "scanner limpo" como prova de ausência de falha: o CSRF agora
também é coberto por teste.

O **A09 Security Logging and Alerting Failures** não é medido pelo ZAP. Ele foi tratado no
Módulo 6 ([`docs/observabilidade.md`](observabilidade.md)).

## Demonstração: o gate bloqueia a reabertura do XSS

Validado localmente antes da entrega
([`docs/evidencias/zap-xss-detectado.txt`](evidencias/zap-xss-detectado.txt)). Basta trocar
`{{ task.description }}` por `{{ task.description | safe }}` em `templates/tasks.html`:

```text
==> 3/4 ZAP Baseline (gate: .zap/rules.tsv)        <- passa: o Baseline é passivo
FAIL-NEW: 0  WARN-NEW: 1  IGNORE: 2  PASS: 65
==> 4/4 ZAP varredura ativa de XSS (gate: risco >= Medium)
::error::ZAP confirmou XSS:
Cross Site Scripting (Persistent) [High (Medium)] em http://127.0.0.1:5000/tasks
```

No PR, o check `DAST - ZAP Baseline + XSS` fica vermelho e a branch protection bloqueia o
merge. O `Testes (pytest)` também reprova, pelo `test_templates_nao_desligam_o_autoescape`
(defesa em profundidade). Ao reverter a mudança, os dois voltam a ficar verdes. Passo a passo
em [`apresentacao-atividade2.md`](apresentacao-atividade2.md).
