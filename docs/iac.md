# Segurança em IaC: Docker Compose e Terraform (Módulo 5)

O workflow [`iac-scan.yml`](../.github/workflows/iac-scan.yml) tem quatro gates, todos
*required checks*. Ele roda em **todo** PR, sem filtro `paths:` (o motivo está no fim
desta página).

| Check | Ferramenta | Escopo | Bloqueia quando |
| --- | --- | --- | --- |
| `IaC - Terraform validate` | `terraform fmt -check` + `validate` (imagem fixada por digest, `-backend=false`, lock file somente leitura) | `infra/` | código mal formatado ou inválido |
| `IaC - Checkov` | Checkov 3.3.30 (`requirements-iac.txt`) | Terraform, Dockerfile, workflows do GitHub Actions | qualquer FAILED; ou `#checkov:skip`/`#trivy:ignore` **sem justificativa** |
| `IaC - Trivy config` | Trivy 0.76.0 (digest) | repositório inteiro | qualquer misconfiguration, **em qualquer severidade** |
| `IaC - Politica do Compose` | [`scripts/check-compose.py`](../scripts/check-compose.py) | `docker-compose.yml` e `docker-compose.observability.yml` | qualquer regra da política violada sem exceção justificada |

Prova do gate no GitHub, negativo → positivo: [PR #21](https://github.com/weynne/taskflow-devsecops/pull/21). O bucket público
e o banco exposto deixaram 3 gates vermelhos; o revert voltou tudo ao verde. Detalhes em
[`evidencias/demos-negativo-positivo.md`](evidencias/demos-negativo-positivo.md).

## Docker Compose

Checkov e Trivy config **não analisam** arquivos Compose. Para o Compose não ficar fora do
gate, o grupo escreveu um verificador de política. Ele lê o modelo já normalizado pelo
próprio Docker (`docker compose config --no-interpolate`), então anchors e merges são
resolvidos e nenhum segredo do `.env` é lido. As regras cobrem exatamente o que o laboratório
pede:

| Regra | Risco mitigado | `docker-compose.yml` |
| --- | --- | --- |
| `segredo-via-env` | senha/chave escrita no YAML versionado | `${VAR:?defina no .env}`: o compose **não sobe** com segredo vazio; só o `.env.example` é versionado |
| `banco-sem-porta`, `banco-rede-interna` | banco acessível do host/internet | `db` sem `ports:` e só na rede `backend` (`internal: true`, sem rota para fora) |
| `porta-loopback` | serviço exposto em todas as interfaces | `127.0.0.1:5000:5000` |
| `read-only` | persistência/adulteração após comprometimento | `read_only: true` + `tmpfs` (`noexec,nosuid`) + volumes só onde há dado |
| `cap-drop`, `no-new-privileges`, `usuario-nao-root` | escalonamento de privilégio | `cap_drop: [ALL]`, `no-new-privileges:true`, `user: 10001` (web) e `70` (postgres) |
| `limites` | DoS local esgotando o host | `deploy.resources.limits` (cpus, memória, pids) |
| `healthcheck` | container "travado" não detectado | `healthcheck` nos dois serviços + `depends_on: condition: service_healthy` |
| `sem-docker-sock` | comprometimento do container vira root no host | nenhum serviço monta o `docker.sock` (nem o Promtail) |
| `imagem-fixada` | build não reprodutível | `postgres:17-alpine@sha256:...`; `web` é build local do Dockerfile endurecido |

Exceções são declaradas no próprio serviço, com um label
`seguranca.excecao.<regra>: "<justificativa>"` de no mínimo 40 caracteres. O relatório
mostra cada exceção, como faria com um `#checkov:skip`. Hoje há uma: o Promtail roda como
root para ler os logs do Docker (`0640 root`), sem nenhuma capability e com o diretório
montado somente leitura. Essa foi a alternativa escolhida para **não** montar o `docker.sock`
(ver [`observabilidade.md`](observabilidade.md)).

**Antes × depois** ([`evidencias/compose-politica.txt`](evidencias/compose-politica.txt)):
a versão insegura do laboratorio tem 20 falhas de política (segredos no YAML, `5432` e `5000`
publicadas em todas as interfaces, `docker.sock` montado, `postgres:latest`, sem limites,
sem healthcheck, root). Os dois arquivos da entrega têm **0 falhas** (61 PASS e 1 exceção
justificada).

Verificação em execução ([`evidencias/compose-verificacao.txt`](evidencias/compose-verificacao.txt)):

```text
host -> 127.0.0.1:5432: recusada (porta nao publicada)
web -> db:5432: ok via rede backend
rootfs web: touch: cannot touch '/teste': Read-only file system
db -> internet: bloqueado (rede internal)
web uid / CapEff: 10001 0000000000000000      <- nenhuma capability
```

## Terraform (`infra/`)

O `main.insecure.tf` do laboratório (FALHAS 1 a 7) foi corrigido em
[`infra/main.tf`](../infra/main.tf). Cada correção tem um comentário
`CORRIGIDO (FALHA N)`. Não há `apply` (não existe conta AWS no curso): a verificação é
feita com `terraform validate` e os scanners.

| Falha | Antes | Depois | Regras que deixaram de falhar |
| --- | --- | --- | --- |
| 1 | sem tags | `default_tags` (Project, Environment, Owner, ManagedBy) no provider | — |
| 2 | bucket público (`public-read`, public access block desligado) | public access block com os 4 campos `true`, `BucketOwnerEnforced` (ACLs desativadas), policy negando acesso sem TLS | CKV_AWS_20/53/54/55/56, CKV2_AWS_6 · AWS-0086/87/91/92/93 |
| 3 | sem criptografia em repouso | SSE-KMS com chave gerenciada pelo cliente (rotação anual, `deletion_window` de 30 dias) | CKV_AWS_145 · AWS-0132 |
| 4 | sem versionamento | versionamento + lifecycle das versões antigas | CKV_AWS_21, CKV2_AWS_61 · AWS-0090 |
| 5 | sem logging | access logging para um bucket de logs dedicado (privado, versionado, retenção de 365 dias) | CKV_AWS_18 · AWS-0089 |
| 6 | security group com 22 e 5432 abertos para `0.0.0.0/0` e saída livre | só 443, a partir de `var.allowed_ingress_cidr` (a **validação** recusa `0.0.0.0/0`); saída só para o Postgres na VPC; descrição em cada regra | CKV_AWS_24/23/382 · AWS-0104/0107/0124 |
| 7 | `access_key`/`secret_key` no provider | nenhuma credencial no código (cadeia padrão da AWS: env, perfil, OIDC no CI) | CKV_AWS_41 |

| Scanner | Linha de base insegura | `infra/` corrigido |
| --- | --- | --- |
| Checkov | **17 FAILED**, 8 passed | **0 FAILED**, 42 passed, 7 skipped (justificados) |
| Trivy config | **13 falhas** (1 CRITICAL, 7 HIGH, 1 MEDIUM, 4 LOW) | **0 falhas**, em todas as severidades |
| `terraform validate` | — | `Success! The configuration is valid.` |

Evidências: [`checkov-terraform-antes.txt`](evidencias/checkov-terraform-antes.txt),
[`trivy-terraform-antes.txt`](evidencias/trivy-terraform-antes.txt),
[`checkov-trivy-terraform-depois.txt`](evidencias/checkov-trivy-terraform-depois.txt).

### Skips justificados

Todo skip está **no próprio código**, na linha do recurso. O job do Checkov reprova
qualquer `#checkov:skip`/`#trivy:ignore` sem texto de justificativa (mínimo de 20
caracteres).

| Recurso | Regra | Justificativa |
| --- | --- | --- |
| `aws_s3_bucket.relatorios`, `.logs` | CKV_AWS_144 (replicação entre regiões) | fora do escopo do laboratório (custo e segunda região); a recuperação vem do versionamento |
| `aws_s3_bucket.relatorios`, `.logs` | CKV2_AWS_62 (notificação de eventos) | não há consumidor de eventos; notificação sem destino não acrescenta controle |
| `aws_s3_bucket.logs` | CKV_AWS_18 · AWS-0089 (logging) | é o bucket **de destino** dos logs; logar nele mesmo cria um laço |
| `aws_s3_bucket.logs` | CKV_AWS_145 · AWS-0132 (KMS) | a entrega de *server access logs* do S3 só suporta SSE-S3 (AES256) no bucket de destino |
| `aws_security_group.app` | CKV2_AWS_5 (SG anexado) | o SG é anexado no módulo de compute, fora do escopo deste laboratório |

### Riscos que continuam fora do código

- **State do Terraform**: guarda atributos em texto puro. O `.gitignore` bloqueia
  `*.tfstate` e `*.tfvars`. Num uso real, o backend seria remoto (S3 criptografado com KMS +
  lock), com acesso restrito.
- **Lock file versionado** (`infra/.terraform.lock.hcl`, com hashes para linux, macOS e
  Windows): o CI usa `-lockfile=readonly`, então um provider diferente do revisado falha o
  `init`.

## Por que o `iac-scan.yml` não tem filtro `paths:`

O exemplo da aula dispara só quando um `**/*.tf` muda. Mas os quatro jobs são **required
checks**. Com o filtro, um PR que não toca em Terraform nunca recebe esses checks e fica
travado em "Expected — waiting for status".

As alternativas e a escolha do grupo:

| Opção | Problema |
| --- | --- |
| `paths:` + required check | trava PRs sem IaC (o problema descrito acima) |
| `paths:` sem marcar como required | o gate vira opcional: um PR de IaC poderia ser mergeado com o scan vermelho |
| job "sempre verde" quando nada muda (`dorny/paths-filter`) | mais uma action de terceiro e lógica condicional para manter |
| **rodar sempre** ✅ | ~1 min por PR; em troca, também pega regressão no Dockerfile, no Compose e nos workflows, que o filtro `*.tf` ignoraria |
