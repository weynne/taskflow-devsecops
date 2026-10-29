# Roteiro da apresentação: Atividade 2 (~10 min)

Foco em resultado, não em YAML. A rubrica pede que **todos falem**. A divisão abaixo segue
as frentes do [`CODEOWNERS`](../.github/CODEOWNERS); ajuste se o grupo preferir.

| # | Bloco (tempo) | Quem fala | O que mostrar |
| --- | --- | --- | --- |
| 1 | Contexto (1 min) | Weynne | o que mudou desde a Atividade 1: DAST, IaC e observabilidade; agora são 12 checks obrigatórios |
| 2 | Demo ao vivo do DAST (2,5 min) | Jéssica | PR reabre o XSS → ZAP acusa → merge bloqueado → revert → verde |
| 3 | IaC (1,5 min) | Diego | um achado do Checkov/Trivy e a correção que o fez sumir |
| 4 | **Incidente ao vivo** (4 min) | Weynne + Jéssica | força bruta → alerta → query do runbook no Grafana → as 4 fases |
| 5 | Decisão técnica e trade-off (1 min) | Diego | DAST sempre roda + XSS ativo, ou Promtail sem `docker.sock` |

## Preparação (no dia anterior)

- [ ] `docker pull` de todas as imagens (ZAP, Loki, Promtail, Grafana, Postgres) para não
  depender da rede da sala.
- [ ] `.env` preenchido (inclusive `ALUNO_PASSWORD` e `GRAFANA_ADMIN_PASSWORD`).
- [ ] Stack no ar e saudável:
  `docker compose up --build -d && docker compose -f docker-compose.observability.yml up -d`.
- [ ] Grafana logado em <http://127.0.0.1:3000>, dashboard *TaskFlow - Seguranca* aberto
  (últimos 15 min, atualização a cada 10 s).
- [ ] Branch da demo do DAST **já empurrada** e o PR **já aberto**, com o run vermelho
  concluído (o job leva ~5 min, mais do que o bloco inteiro).
- [ ] Branch protection com os 12 checks e a fase 2 (aprovação de Code Owner) ligada.
- [ ] **Plano B gravado**: um vídeo curto de cada demo e prints (veja abaixo).

## 2. Demo do DAST

Antes da aula:

```bash
git switch main && git pull
git switch -c demo/xss-ao-vivo
sed -i 's/{{ task.description }}/{{ task.description | safe }}/' templates/tasks.html
git commit -am "feat: permite formatacao HTML na descricao da tarefa"
git push -u origin demo/xss-ao-vivo      # abrir o PR para a main
```

Ao vivo, no PR:

1. Check `DAST - ZAP Baseline + XSS` **vermelho**. No log aparece
   `::error::ZAP confirmou XSS: Cross Site Scripting (Persistent) [High] em .../tasks`.
2. Ponto para comentar: o **Baseline passou** (é passivo); quem pegou foi a varredura ativa
   de XSS. Esse é o motivo de existir a etapa 4 do script.
3. Artefato `zap-reports` → `zap-xss.html` com o payload do ZAP.
4. `Testes (pytest)` também vermelho (`test_templates_nao_desligam_o_autoescape`): defesa
   em profundidade.
5. Botão de merge bloqueado.
6. `git revert --no-edit HEAD && git push` → os checks voltam a ficar verdes (ou mostre um
   run verde já concluído, porque o DAST leva ~5 min).

## 3. IaC

Mostrar [`docs/iac.md`](iac.md) e uma correção concreta. Sugestão: FALHA 2, bucket
público.

```bash
cd infra
sed -i '0,/restrict_public_buckets = true/s//restrict_public_buckets = false/' main.tf
checkov -d . --framework terraform --compact --quiet | grep -A1 CKV_AWS_56   # FAILED
trivy config . | grep AWS-0093                                                # HIGH
git checkout main.tf                                                          # corrige
checkov -d . --framework terraform --compact --quiet | tail -1                # 0 failed
```

Fechar com o gate do Compose: `python3 scripts/check-compose.py docker-compose.yml`. Em
seguida, mostrar o antes (20 FAIL) em
[`evidencias/compose-politica.txt`](evidencias/compose-politica.txt).

## 4. Incidente ao vivo (o bloco mais importante)

1. **Ataque** (terminal):

   ```bash
   python3 scripts/simular-forca-bruta.py --tentativas 25
   BRUTEFORCE_SENHA_REAL="<ALUNO_PASSWORD>" \
     python3 scripts/simular-forca-bruta.py --usuario aluno --tentativas 15 --sucesso-no-fim
   ```

2. **Detecção**: no dashboard, o painel *Falhas de login por IP* passa da linha vermelha
   (10). Em ~1 min, **Alerting → Alert rules** mostra o alerta disparado para o IP.
3. **Análise**: **Explore → Loki**, colar as queries **do runbook**, na ordem:
   - Q1 (detecção): quantas falhas por IP;
   - Q2: quais contas, `bad_password` ou `unknown_user`;
   - Q3: o IP conseguiu entrar? Sim, `aluno` → **severidade Alta**.
4. **Contenção**: trocar a senha do `aluno` (comando no runbook) e mostrar que **a sessão
   do atacante continua válida**. Rotacionar a `TASKFLOW_SECRET_KEY` no `.env` e rodar
   `docker compose up -d web`; a sessão cai.
5. **Pós-incidente**: a linha do tempo e a ação nº 1 (rate limit no login) do
   [runbook](runbook-login-bruteforce.md#fase-4--atividade-pós-incidente).

## 5. Decisão técnica e trade-off (escolher uma)

- **DAST: Baseline + varredura ativa só de XSS.** O Baseline sozinho não detecta XSS. O
  *full scan* detectaria, mas leva mais tempo e roda dezenas de regras irrelevantes.
  *Trade-off:* ~1 min a mais por PR, com um ataque real, mas restrito a XSS e contra uma
  instância efêmera. ([dast.md](dast.md#decisões-de-desenho))
- **IaC sem filtro `paths:`.** Required check + `paths:` trava PRs que não tocam em IaC.
  *Trade-off:* ~1 min de CI em todo PR, em troca de um gate que nunca fica "pendente" e que
  também cobre Dockerfile, Compose e workflows. ([iac.md](iac.md#por-que-o-iac-scanyml-não-tem-filtro-paths))
- **Promtail sem `docker.sock`.** A descoberta pelo socket é o padrão da documentação, mas
  equivale a root no host. Lemos os arquivos de log em modo somente leitura e identificamos
  o serviço pelos `attrs` do driver. *Trade-off:* o Promtail roda como root (sem nenhuma
  capability) e depende do driver `json-file`. ([observabilidade.md](observabilidade.md#arquitetura))

## Plano B

| Demo | Se falhar | Evidência pronta |
| --- | --- | --- |
| DAST | rodar `DAST_PASSWORD=... ./scripts/dast-scan.sh` localmente contra a imagem com `\| safe` | [`zap-xss-detectado.txt`](evidencias/zap-xss-detectado.txt), [`zap-depois.txt`](evidencias/zap-depois.txt) |
| IaC | mostrar as saídas salvas | [`checkov-terraform-antes.txt`](evidencias/checkov-terraform-antes.txt), [`checkov-trivy-terraform-depois.txt`](evidencias/checkov-trivy-terraform-depois.txt) |
| Incidente | queries direto no Loki: `curl -sG 127.0.0.1:3100/loki/api/v1/query --data-urlencode 'query=<Q1>'` | [`forca-bruta-deteccao.txt`](evidencias/forca-bruta-deteccao.txt) + vídeo/prints do Grafana |
