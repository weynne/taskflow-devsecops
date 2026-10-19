# Hardening do container (e do SO)

Escopo: `Dockerfile` da TaskFlow, flags de runtime (`scripts/docker-run-seguro.sh`)
e o gate de imagem do pipeline (`.github/workflows/container.yml`).
Medições feitas em 18/10/2026 com Trivy 0.76.0.

## 1. As seis falhas do Dockerfile original

| Falha original | Correção aplicada | Onde |
| --- | --- | --- |
| **FALHA 1** — `FROM python:latest` sem versão fixada | `python:3.12-slim` com **tag + digest** (`@sha256:a6e3…`) e build **multi-stage** (venv no estágio `build`, só o venv é copiado para o `runtime`). O Dependabot (ecossistema `docker`) propõe a atualização do digest. | `Dockerfile` |
| **FALHA 2** — roda como root | Usuário/grupo `taskflow` (UID/GID 10001), sem shell (`/usr/sbin/nologin`) e sem home; `USER taskflow`. O código fica com dono root e só leitura para o processo; apenas `/app/data` é gravável. | `Dockerfile` |
| **FALHA 3** — sem verificação de integridade das dependências | `requirements.txt` gerado pelo `pip-compile --generate-hashes` e instalado com `pip install --require-hashes --no-cache-dir`. O `pip` é removido do venv e do sistema na imagem final. | `Dockerfile`, `requirements.in/.txt` |
| **FALHA 4** — `ENV ADMIN_PASSWORD=<valor>` (senha em texto puro) | Removido. `TASKFLOW_SECRET_KEY` e `ADMIN_PASSWORD` entram **em runtime** (`docker run -e`/`--env-file`). O pipeline falha se `docker history` mostrar `PASSWORD=`/`SECRET=`/`TOKEN=`. | `Dockerfile`, `container.yml` |
| **FALHA 5** — `EXPOSE` do servidor de desenvolvimento | `EXPOSE 5000` mantido só como documentação; quem escuta é o gunicorn. O script publica a porta só em `127.0.0.1`. | `Dockerfile`, script |
| **FALHA 6** — `python app.py` com `debug=True` | `gunicorn --preload wsgi:app` (2 workers, sem control socket) e `debug` removido do código. `HEALTHCHECK` adicionado. | `Dockerfile`, `wsgi.py`, `app.py` |

`trivy config .` no Dockerfile novo: **0 misconfigurations** (gate no pipeline).

## 2. Trivy: antes × depois

Comando (o mesmo para as duas imagens):

```bash
docker build -t taskflow:vuln <commit da linha de base>   # Dockerfile original
docker build -t taskflow:hardened .                        # Dockerfile atual
trivy image --severity HIGH,CRITICAL taskflow:vuln     | tee /tmp/trivy-antes.txt
trivy image --severity HIGH,CRITICAL taskflow:hardened | tee /tmp/trivy-depois.txt
```

| Métrica | `taskflow:vuln` (antes) | `taskflow:hardened` (depois) |
| --- | --- | --- |
| Imagem base | `python:latest` (no dia: Python **3.15**, Debian 13 completo) | `python:3.12-slim@sha256:a6e3…` |
| Tamanho | 1,66 GB | 188 MB |
| SO — CRITICAL | **17** | **0** |
| SO — HIGH | **357** | 44 (nenhuma com correção publicada) |
| SO — HIGH/CRITICAL **com correção disponível** | 39 | **0** |
| Bibliotecas Python — HIGH/CRITICAL | 14 (Flask 0.12.2, Werkzeug 0.15.4, PyYAML 5.1, requests 2.6.0) | **0** |
| Gate do pipeline (`--ignore-unfixed --exit-code 1`) | falha | **passa** |

Evidências completas: [`evidencias/trivy-antes-resumo.txt`](evidencias/trivy-antes-resumo.txt),
[`evidencias/trivy-depois.txt`](evidencias/trivy-depois.txt) e
[`evidencias/trivy-depois-gate.txt`](evidencias/trivy-depois-gate.txt).

Observação: com `latest`, a mesma linha `FROM` passou a puxar Python 3.15 sem nenhum aviso.
Esse é o problema de reprodutibilidade da FALHA 1, visto na prática.

### Risco aceito: 44 HIGH sem correção

As 44 HIGH restantes são de pacotes do Debian 13 (`util-linux`/`libmount1`/`login`
— CVE-2026-76642; `ncurses` — CVE-2025-69720; `libsystemd0`/`libudev1` —
CVE-2026-16742; `perl-base` — CVE-2026-9538, entre outras) com status `affected` ou
`fix_deferred`: **o Debian ainda não publicou versão corrigida**, então não há o que
atualizar.

Decisão do grupo: o gate usa `--ignore-unfixed`. Essas CVEs **não bloqueiam**, mas:

- continuam no relatório completo publicado como artefato em cada run (`container-reports`);
- o workflow roda **toda segunda-feira** (`schedule`): quando o Debian lançar a correção, a
  CVE passa a ter `FixedVersion` e o gate quebra, forçando um rebuild;
- a maioria afeta binários que a TaskFlow não executa (`mount`, `login`, `perl`), e o
  container roda sem capabilities, como não-root e com rootfs read-only, o que reduz
  bastante a explorabilidade.

Próximo passo de maturidade: imagem **distroless** (ex.: `gcr.io/distroless/python3`), que
não traz shell nem esses pacotes.

`.trivyignore` existe para exceções pontuais **com correção disponível** e está vazio:
nenhuma foi necessária.

## 3. `docker history`: antes × depois

```bash
docker history --no-trunc taskflow:vuln
docker history --no-trunc taskflow:hardened
```

**Antes** — o segredo aparece em texto puro em uma camada
([evidência completa](evidencias/docker-history-antes.txt)):

```text
CMD ["python" "app.py"]
EXPOSE [5000/tcp]
ENV ADMIN_PASSWORD=***                           <-- segredo gravado na imagem
COPY . . # buildkit                              <-- copia tudo, inclusive .git
RUN /bin/sh -c pip install -r requirements.txt
```

**Depois** — nenhum segredo, usuário não-root, cópia seletiva
([evidência completa](evidencias/docker-history-depois.txt)):

```text
CMD ["gunicorn" "--bind" "0.0.0.0:5000" "--workers" "2" "--preload" ... "wsgi:app"]
HEALTHCHECK {Test:[CMD python -c import urllib.request; ...]}
USER taskflow
EXPOSE [5000/tcp]
COPY templates/ templates/ # buildkit
COPY app.py wsgi.py ./ # buildkit
COPY /opt/venv /opt/venv # buildkit
RUN /bin/sh -c groupadd --system --gid 10001 taskflow ...
ENV PATH=/opt/venv/bin:... PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TASKFLOW_DB_PATH=/app/data/taskflow.db
```

O pipeline automatiza essa checagem no step **"Nenhum segredo nas camadas da imagem"**.

## 4. Flags de segurança em runtime

`scripts/docker-run-seguro.sh` (adaptado de `codigo/hardening/docker-run-seguro.sh` do
repositório da disciplina) é usado localmente **e** pelo smoke test do pipeline:

| Flag | Efeito |
| --- | --- |
| `--read-only` | rootfs somente leitura: não dá para alterar binários nem persistir artefatos |
| `-v taskflow-dados:/app/data` | único caminho persistente gravável (SQLite) |
| `--tmpfs /tmp:rw,noexec,nosuid,size=16m` | temporários em memória, sem execução |
| `--cap-drop=ALL` | nenhuma Linux capability (a porta 5000 dispensa `NET_BIND_SERVICE`) |
| `--security-opt=no-new-privileges` | bloqueia escalonamento via binários setuid |
| `--memory=256m --cpus=0.5 --pids-limit=100` | limita abuso de recursos e fork bomb |
| `--user 10001:10001` | reforça o não-root mesmo se a imagem mudar |
| `-p 127.0.0.1:5000:5000` | publica só na interface local do host |
| `--env-file .env` ou `-e NOME` | segredos em runtime, sem valor na linha de comando |

O smoke test do CI verifica: a aplicação responde em `/login`, `id -u` ≠ 0, escrever em
`/app` falha (read-only) e `/debug/info` retorna 404.

Execução local verificada:

```text
$ ./scripts/docker-run-seguro.sh
login GET 200
login POST 302 -> /tasks
debug 404
uid=10001(taskflow) gid=10001(taskflow) groups=10001(taskflow)
touch: cannot touch '/app/x': Read-only file system
health: healthy
```

## 5. Hardening do SO — Lynis

Auditoria da máquina de desenvolvimento do grupo (Ubuntu 26.04 em WSL2), executada
**sem root** (modo limitado):

```bash
git clone --depth 1 https://github.com/CISOfy/lynis.git && cd lynis
./lynis audit system --quick
```

Resultado: **Hardening index 67/100**, 252 testes, 1 warning, 32 sugestões.

| Achado (ID Lynis) | Leitura do grupo |
| --- | --- |
| NETW-2705 (warning) — menos de 2 nameservers respondendo | Característica do WSL (DNS gerado pelo Windows). Em servidor real: configurar resolvedor secundário. |
| AUTH-9262 / AUTH-9286 — sem PAM de força de senha, sem idade mínima/máxima de senha | Aplicável a servidor: `libpam-pwquality` e `PASS_MAX_DAYS`/`PASS_MIN_DAYS` em `/etc/login.defs`. |
| AUTH-9328 — umask padrão 022 | Recomendado 027 em servidores. |
| ACCT-9628 — `auditd` desabilitado | Relevante para resposta a incidentes (Atividade 2). |
| FINT-4350 / HRDN-7230 — sem integridade de arquivos nem antimalware | AIDE/rkhunter num servidor de produção. |
| NETW-3200 — protocolos `dccp`, `sctp`, `rds`, `tipc` carregáveis | Desabilitar via `modprobe.d` se não usados (CIS L1). |
| KRNL-5788 / FILE-6310 — sem `/vmlinuz`, sem partições separadas | Próprios do WSL (kernel e disco gerenciados pelo Windows); não se aplicam. |

O container não depende desses itens: ele roda isolado com as flags da seção 4. O Lynis
entra como diagnóstico do host, não como gate do pipeline.
