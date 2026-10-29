# Runbook: força bruta no login da TaskFlow

| | |
| --- | --- |
| **ID** | RB-001 · `runbook=login-bruteforce` |
| **Modelo** | NIST SP 800-61 (quatro fases do ciclo de resposta a incidentes) |
| **Condição de disparo** | **mais de 10 falhas de login do mesmo IP em 5 minutos** (alerta *"TaskFlow - forca bruta no login"* no Grafana), ou um analista vê o padrão no dashboard |
| **Severidade inicial** | **Média**. Sobe para **Alta** se a Q3 mostrar login com sucesso a partir do IP atacante (conta comprometida). |
| **Dono** | plantão de segurança do grupo WJD (substituto: dono do repositório) |
| **Exercitado em** | 2026-10-27, simulação registrada em [`evidencias/forca-bruta-deteccao.txt`](evidencias/forca-bruta-deteccao.txt) |

**Query de detecção** (Grafana → Explore → Loki, ou o primeiro painel do dashboard
*TaskFlow - Seguranca*):

```logql
sum by (client_ip) (count_over_time({service="web", event="login_failure"} | json [5m]))
```

---

## Fase 1 — Preparação

O que precisa existir **antes** do incidente. Na TaskFlow, tudo está versionado:

- [x] Logs JSON com `event`, `user`, `reason`, `client_ip` e `request_id` em cada
  login, sem senha ([`observabilidade.md`](observabilidade.md)).
- [x] Coleta Promtail → Loki, com retenção de 7 dias, e Grafana com dashboard e alerta
  provisionados como código.
- [x] Regra de alerta com o limiar deste runbook
  ([`bruteforce.yml`](../observability/grafana/provisioning/alerting/bruteforce.yml)).
- [x] Acesso do plantão ao host do Compose e ao `.env` (para rotacionar segredos).
- [x] Simulador para treinar: [`scripts/simular-forca-bruta.py`](../scripts/simular-forca-bruta.py)
  (só ataca `localhost`).
- [ ] Contact point do alerta (e-mail/Slack). Não configurado no laboratório: o alerta só
  aparece na UI do Grafana. Ver ações pós-incidente.

## Fase 2 — Detecção e análise

1. **Confirmar o disparo.** Abra o alerta ou rode a query de detecção acima. Anote o
   `client_ip`, o pico e o horário de início. Na simulação: `172.20.0.1`, 40 falhas.
2. **Descobrir os alvos e o tipo de ataque** (Q2):

   ```logql
   sum by (client_ip, user, reason) (count_over_time({service="web", event="login_failure"} | json [30m]))
   ```

   - Muitos usuários diferentes com `unknown_user` → enumeração/*spraying*.
   - Poucos usuários com `bad_password` → força bruta direcionada a contas reais.
   - Simulação: `admin` 25× e `aluno` 15×, ambos `bad_password` (contas reais).
3. **Verificar se alguma tentativa deu certo** (Q3). Esta é a pergunta que define a
   severidade:

   ```logql
   sum by (client_ip, user) (count_over_time({service="web", event="login_success"} | json [30m]))
     and on (client_ip)
   sum by (client_ip) (count_over_time({service="web", event="login_failure"} | json [30m]))
   ```

   Resultado vazio → tentativa sem sucesso (Média). Qualquer linha → **conta comprometida
   (Alta)**. Simulação: `aluno` entrou depois de 15 falhas. **Severidade Alta.**
4. **Delimitar o impacto da conta comprometida** (Q4): o que a sessão fez depois de
   entrar.

   ```logql
   {service="web"} | json | user_id="<id>" | line_format "{{.timestamp}} {{.event}} {{.method}} {{.path}} {{.status}} req={{.request_id}}"
   ```

   Simulação: só o `POST /login 302`; nenhuma tarefa lida ou criada.
5. **Descartar falso positivo.** O IP é de um teste interno, de um monitor sintético ou de
   um usuário legítimo que esqueceu a senha (poucas falhas e depois um sucesso, sem padrão
   de lista)? Se for, documente e encerre.
6. **Registrar** em um ticket: horário de detecção, IP, contas, contagens, severidade e os
   `request_id` relevantes.

> **Atenção ao IP.** No Compose local, todo acesso feito a partir do host chega à aplicação
> como o gateway da rede `frontend` (`172.20.0.1` na simulação). Em produção, atrás de um
> proxy, configure `ProxyFix` com o número exato de saltos confiáveis para ver o IP real
> (comentário em `client_ip()` no `app.py`). Nunca confie em `X-Forwarded-For` cru.

## Fase 3 — Contenção, erradicação e recuperação

**Contenção (minutos):**

1. **Bloquear a origem.** Em produção: regra de *deny* no WAF/balanceador ou no security
   group (`infra/` só permite `var.allowed_ingress_cidr`). No host do laboratório:

   ```bash
   sudo iptables -I DOCKER-USER -s <IP_ATACANTE> -j DROP     # desfazer: -D no lugar de -I
   ```

   No laboratório o "atacante" é o próprio gateway do host, então o bloqueio também
   derrubaria o acesso legítimo. Na simulação, esta etapa foi **descrita, não executada**.
2. **Conta comprometida: trocar a senha** (executado na simulação):

   ```bash
   docker compose exec -T web python - <<'EOF'
   import os, secrets, sqlite3
   from werkzeug.security import generate_password_hash
   nova = secrets.token_urlsafe(16)
   db = sqlite3.connect(os.environ["TASKFLOW_DB_PATH"])
   db.execute("UPDATE users SET password = ? WHERE username = ?",
              (generate_password_hash(nova), "aluno"))
   db.commit()
   print("nova senha temporaria:", nova)   # entregar ao dono por canal seguro
   EOF
   ```

3. **Derrubar as sessões já abertas** (executado na simulação). A sessão do Flask é um
   cookie assinado, sem estado no servidor: **trocar a senha não expulsa o atacante**, e a
   simulação comprovou isso (a sessão continuou em 200). A única forma de invalidar as
   sessões é **rotacionar a `TASKFLOW_SECRET_KEY`**:

   ```bash
   # edite TASKFLOW_SECRET_KEY no .env com um valor novo:
   python3 -c "import secrets; print(secrets.token_urlsafe(48))"
   docker compose up -d web        # recria o container com a chave nova
   ```

   Resultado: a sessão do atacante passou a receber `302 → /login`. Efeito colateral
   aceito: **todos** os usuários precisam logar de novo. Cuidado: se a variável estiver
   exportada no shell, ela tem precedência sobre o `.env` e o container **não** é recriado.
   Confirme com `docker compose ps` (o tempo de *Up* deve zerar).

**Erradicação:**

4. Rodar de novo a Q1 e a Q3: nenhuma falha nova do IP bloqueado e nenhum sucesso novo.
5. Se o atacante criou ou alterou dados (Q4), reverter e preservar uma cópia dos registros
   como evidência.
6. Atacar a causa raiz. Hoje a aplicação **não limita tentativas**, e é isso que torna a
   força bruta viável. A correção está nas ações pós-incidente.

**Recuperação:**

7. Confirmar a saúde com `docker compose ps` (tudo `healthy`) e a Q5 (status HTTP).
8. Manter a Q1 e a Q3 em observação reforçada por 24 h, porque o atacante pode voltar de
   outro IP.
9. Avisar o dono da conta comprometida: senha temporária e troca no próximo acesso.

## Fase 4 — Atividade pós-incidente

**Linha do tempo da simulação (2026-10-27, horário de Brasília):**

| Hora | Evento |
| --- | --- |
| 21:16:10 | início do ataque contra `admin` (25 tentativas) |
| 21:16:15 | ataque contra `aluno` (15 falhas + 1 sucesso às 21:16:18) |
| 21:17:10 | alerta *Alerting* no Grafana para `172.20.0.1` (40 falhas / 5 min) |
| ~21:18 | análise: Q1 → Q2 → Q3 (conta `aluno` comprometida) → Q4 (sem ações após o login) |
| 21:25 | contenção: senha do `aluno` trocada; `SECRET_KEY` rotacionada (`web` recriado às 21:25:17); sessões derrubadas |

**Tempo até detectar (MTTD):** ~1 min, o intervalo de avaliação da regra.

**Lições aprendidas e ações** (cada uma vira uma issue):

| # | Ação | Por quê | Prioridade |
| --- | --- | --- | --- |
| 1 | *Rate limit* por IP e por conta no `/login` (ex.: 5 tentativas/min, *lockout* progressivo) | a aplicação aceitou 40 tentativas em 8 s | Alta |
| 2 | Política de senha (comprimento mínimo, lista de senhas vazadas) e MFA para `admin` | `aluno` caiu com uma senha da lista | Alta |
| 3 | Sessões com estado no servidor (ou versão de sessão por usuário) | invalidar um único usuário hoje exige derrubar todos | Média |
| 4 | Contact point do alerta (Slack/e-mail do plantão) | o alerta só existe na UI | Média |
| 5 | `ProxyFix` + IP real quando houver proxy/TLS na frente | sem isso, todos os acessos parecem vir do mesmo IP | Média |
| 6 | Repetir este exercício a cada trimestre e após mudanças no login | manter o runbook vivo | Baixa |

**Revisão deste runbook:** a cada execução real ou simulada. Atualize as queries se os
nomes de eventos/labels mudarem (eles são testados em `tests/test_security.py`).
