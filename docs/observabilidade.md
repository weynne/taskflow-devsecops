# Observabilidade: logs estruturados, Loki e Grafana (Módulo 6)

## Arquitetura

```text
 docker-compose.yml (projeto "taskflow")          docker-compose.observability.yml
 ┌───────────────────────────────┐                ┌──────────────────────────────────────┐
 │ web (gunicorn + Flask)        │  stdout JSON   │ promtail ── lê /var/lib/docker/      │
 │  uma linha JSON por evento ───┼──► driver ────►│   containers/*/*-json.log (ro)       │
 │ db (postgres)                 │  json-file     │      │ push                          │
 └───────────────────────────────┘  (attrs:       │      ▼                               │
                                     projeto,     │ loki :3100 (127.0.0.1) ◄── grafana   │
                                     serviço)     │                          :3000 (127.0.0.1)
                                                  └──────────────────────────────────────┘
```

- A **aplicação** escreve uma linha JSON por evento no stdout. Ela não conhece o Loki.
- O **Promtail** lê os arquivos do driver `json-file` em modo somente leitura. Ele **não
  monta o `docker.sock`**, que daria controle total do host a quem o comprometesse. O
  serviço é identificado pelo campo `attrs` que o próprio driver grava, graças às opções
  `labels`/`tag` declaradas no `docker-compose.yml`. Linhas de containers de outros
  projetos do host são **descartadas** antes de chegar ao Loki.
- **Labels** (indexados): `project`, `service`, `container`, `stream`, `event`, `level`.
  Todos têm poucos valores possíveis. `client_ip`, `user` e `request_id` têm alta
  cardinalidade e ficam no corpo; a consulta os extrai com `| json`.
- O **Grafana** sobe já configurado (*provisioning* como código): datasource Loki, dashboard
  **TaskFlow - Seguranca** e a regra de alerta de força bruta.

### Como subir

```bash
cp .env.example .env     # preencha TASKFLOW_*, POSTGRES_*, GRAFANA_ADMIN_PASSWORD e ALUNO_PASSWORD
docker compose up --build -d                                  # app + banco
docker compose -f docker-compose.observability.yml up -d      # loki + promtail + grafana
docker compose -f docker-compose.observability.yml ps         # os 3 "healthy"
```

Grafana em <http://127.0.0.1:3000> (usuário e senha do `.env`) → **Dashboards → TaskFlow →
TaskFlow - Seguranca**, ou **Explore → Loki** para as consultas abaixo. A stack segue o mesmo
hardening do Compose da aplicação: portas só em `127.0.0.1`, rootfs read-only, `cap_drop: ALL`,
limites, healthchecks, imagens por digest, Grafana sem acesso anônimo e sem cadastro aberto.

## Logging estruturado na TaskFlow

Implementado em [`app.py`](../app.py) com a biblioteca padrão (`logging` + um `JsonFormatter`),
sem dependência nova. Exemplo real de uma linha:

```json
{"timestamp": "2026-10-28T00:16:18.525+00:00", "level": "WARNING", "logger": "taskflow",
 "event": "login_failure", "request_id": "258dc6ed70b545ed9b9c5c8776388036",
 "user": "aluno", "reason": "bad_password", "client_ip": "172.20.0.1"}
```

| Evento | Nível | Campos (além de `timestamp`, `level`, `request_id`) |
| --- | --- | --- |
| `http_request` | INFO | `method`, `path` (**sem** query string), `status`, `duration_ms`, `client_ip`, `user_id` |
| `login_success` | INFO | `user`, `user_id`, `client_ip` |
| `login_failure` | WARNING | `user` (truncado em 64), `reason` (`bad_password` \| `unknown_user`), `client_ip` |
| `logout` | INFO | `user_id`, `client_ip` |
| `task_created` | INFO | `user_id`, `task_id`, `title_length` (o **conteúdo** da tarefa não é logado) |
| `tasks_listed` | INFO | `user_id`, `count`, `search_used` (booleano; o **termo** buscado não é logado) |
| `csrf_rejected` | WARNING | `path`, `client_ip` |

**`request_id`**: gerado por requisição (`uuid4`). Também é devolvido no cabeçalho
`X-Request-ID`, para o usuário reportar um erro e o time achar a requisição exata. Um
`X-Request-ID` vindo de proxy só é reaproveitado se tiver formato seguro
(`[A-Za-z0-9-]{8,64}`); fora disso, a aplicação gera um novo.

**O que nunca é logado**: senha (nem a errada), cookie, token CSRF, `SECRET_KEY`,
cabeçalho `Authorization`, `request.form` inteiro, query string e conteúdo das tarefas. Há
três camadas de proteção:

1. **Lista explícita**: cada evento declara só os campos que precisa.
2. **Filtro no formatter**: descarta qualquer campo cujo *nome* contenha
   `pass|secret|token|cookie|authorization|csrf`, mesmo que alguém o passe por engano.
3. **JSON**: `json.dumps` escapa quebras de linha, então um username como
   `x\n{"event":"login_success"}` não forja uma linha falsa (*log injection*).

Testes: `test_logs_em_json_com_request_id_e_sem_senha` (faz login com senha errada e certa e
garante que nenhuma das duas aparece no log), `test_campos_sensiveis_sao_descartados_do_log`,
`test_request_id_e_devolvido_e_valida_formato`. Verificação também no Loki, depois da
simulação: buscar pelas senhas tentadas (`senha123`, `admin123`...) e pela senha real retorna
**zero** linhas ([evidência](evidencias/forca-bruta-deteccao.txt)).

## Consultas LogQL usadas pelo grupo

Todas foram executadas contra a stack em funcionamento. Os resultados abaixo são da
simulação registrada em [`evidencias/forca-bruta-deteccao.txt`](evidencias/forca-bruta-deteccao.txt).

### Q1. Quantas falhas de login cada IP gerou nos últimos 5 minutos? (query de detecção do runbook)

```logql
sum by (client_ip) (count_over_time({service="web", event="login_failure"} | json [5m]))
```

Resultado: `{client_ip="172.20.0.1"} 40`. Acima de **10** dispara o alerta e o
[runbook](runbook-login-bruteforce.md). É o painel do topo do dashboard, com a linha de
limiar em vermelho.

### Q2. Quais contas estão sendo atacadas, de onde, e o usuário existe?

```logql
sum by (client_ip, user, reason) (count_over_time({service="web", event="login_failure"} | json [30m]))
```

Resultado: `admin` 25× e `aluno` 15×, ambos `bad_password` e do mesmo IP. Conclusão:
*credential stuffing*/força bruta direcionada a contas que existem. Muitos `unknown_user`
indicariam enumeração de usuários.

### Q3. Algum IP que errou a senha conseguiu entrar? (indício de comprometimento)

```logql
sum by (client_ip, user) (count_over_time({service="web", event="login_success"} | json [30m]))
  and on (client_ip)
sum by (client_ip) (count_over_time({service="web", event="login_failure"} | json [30m]))
```

Resultado: `{client_ip="172.20.0.1", user="aluno"} 1`. A conta `aluno` foi comprometida
depois de 15 tentativas. Essa consulta decide se o incidente passa de "tentativa" para
"conta comprometida" na fase de análise do runbook.

### Q4. O que essa sessão fez depois de entrar? (rastreio por usuário/requisição)

```logql
{service="web"} | json | user_id="2" | event=~"tasks_listed|task_created|logout|http_request"
  | line_format "{{.timestamp}} {{.event}} {{.method}} {{.path}} {{.status}} req={{.request_id}}"
```

Mostra a linha do tempo da conta comprometida e serve para delimitar o impacto. Na
simulação, a única linha é o `POST /login 302` do próprio ataque: a sessão não listou nem
criou tarefas. Com um `request_id` específico, `{service="web"} |= "<request_id>"` traz
todos os eventos daquela requisição.

### Q5. A aplicação está saudável? (erros e latência)

```logql
sum by (status) (count_over_time({service="web", event="http_request"} | json [1m]))
```

```logql
quantile_over_time(0.95, {service="web", event="http_request"} | json duration_ms, path | unwrap duration_ms [5m]) by (path)
```

Picos de `400` sinalizam CSRF rejeitado ou requisições forjadas; `5xx` sinaliza erro de
aplicação. A segunda consulta dá o p95 de latência por rota. Na simulação, `/login` ficou em
~103 ms, dominado pelo custo proposital do hash `scrypt`. Extrair só `duration_ms` e `path`
no `| json` é necessário: com `| json` puro, `request_id` vira label e cada requisição vira
uma série, o que impede a agregação.

## Alerta

[`observability/grafana/provisioning/alerting/bruteforce.yml`](../observability/grafana/provisioning/alerting/bruteforce.yml)
avalia a Q1 a cada minuto. Cada IP acima de 10 falhas em 5 minutos vira uma instância
**Alerting** (*"172.20.0.1 errou o login 40 vezes em 5 minutos"*), com label
`runbook=login-bruteforce`. Sem *contact point* configurado (sem e-mail/Slack no
laboratório), o alerta aparece em **Alerting → Alert rules**. Em produção, ele seria roteado
para o plantão.
