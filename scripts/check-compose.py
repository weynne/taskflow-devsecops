#!/usr/bin/env python3
"""Gate de politica para arquivos Docker Compose (Modulo 5).

Checkov e Trivy config nao analisam docker-compose.yml, entao este script
cobre as regras exigidas no laboratorio e falha (exit 1) se alguma for
violada. Le o modelo ja normalizado pelo proprio Docker Compose
("docker compose config --no-interpolate"), entao anchors/merges sao
resolvidos e nenhum segredo do .env e necessario nem lido.

Excecao: um servico pode declarar o label
    seguranca.excecao.<regra>: "<justificativa com pelo menos 40 caracteres>"
que desliga aquela regra so para ele. A excecao aparece no relatorio,
como os #checkov:skip.

Uso: python3 scripts/check-compose.py docker-compose.yml [outros.yml ...]
"""

import json
import re
import shutil
import subprocess
import sys

SEGREDO = re.compile(r"PASS|SECRET|TOKEN|_KEY$", re.IGNORECASE)
BANCO = re.compile(r"(^|/)(postgres|mysql|mariadb|mongo|redis)[:@]")
INTERPOLADO = re.compile(r"^\$\{[A-Z0-9_]+(:?[-?][^}]*)?\}$")


def carregar(arquivo):
    docker = shutil.which("docker") or sys.exit("docker nao encontrado no PATH")
    saida = subprocess.run(  # noqa: S603 - argumentos fixos, sem shell
        [docker, "compose", "-f", arquivo, "config", "--no-interpolate", "--format", "json"],
        check=True, capture_output=True, text=True,
    ).stdout
    return json.loads(saida)


def regras(nome, svc, redes):
    """Gera (regra, ok, detalhe) para um servico."""
    yield "read-only", svc.get("read_only") is True, "read_only: true"
    yield "cap-drop", "ALL" in svc.get("cap_drop", []), "cap_drop: [ALL]"
    yield ("no-new-privileges",
           "no-new-privileges:true" in svc.get("security_opt", []),
           "security_opt: [no-new-privileges:true]")
    hc = svc.get("healthcheck", {})
    yield "healthcheck", bool(hc.get("test")) and not hc.get("disable"), "healthcheck definido"
    limites = svc.get("deploy", {}).get("resources", {}).get("limits", {})
    yield ("limites", bool(limites.get("cpus")) and bool(limites.get("memory")),
           "deploy.resources.limits com cpus e memory")
    yield "nao-privilegiado", not svc.get("privileged"), "sem privileged: true"
    yield ("rede-propria", svc.get("network_mode") != "host" and svc.get("pid") != "host",
           "sem network_mode/pid host")
    socks = [v for v in svc.get("volumes", []) if "docker.sock" in str(v.get("source", ""))]
    yield "sem-docker-sock", not socks, "docker.sock nao montado"
    expostas = [p for p in svc.get("ports", []) if p.get("host_ip") != "127.0.0.1"]
    yield "porta-loopback", not expostas, "portas publicadas apenas em 127.0.0.1"
    usuario = str(svc.get("user", "")).split(":")[0]
    yield "usuario-nao-root", usuario not in ("", "0", "root"), "user definido e diferente de root"
    imagem = svc.get("image", "")
    yield ("imagem-fixada", "build" in svc or "@sha256:" in imagem,
           "imagem com digest (@sha256) ou build local")
    hardcoded = [k for k, v in (svc.get("environment") or {}).items()
                 if SEGREDO.search(k) and v and not INTERPOLADO.match(str(v))]
    yield "segredo-via-env", not hardcoded, f"segredos interpolados do .env {hardcoded or ''}"
    if BANCO.search(imagem):
        yield "banco-sem-porta", not svc.get("ports"), "banco sem porta publicada no host"
        externas = [r for r in svc.get("networks", {}) if not redes.get(r, {}).get("internal")]
        yield "banco-rede-interna", not externas, f"banco so em redes internal {externas or ''}"


def verificar(arquivo):
    modelo = carregar(arquivo)
    redes = modelo.get("networks", {})
    falhas = 0
    print(f"== {arquivo}")
    for nome, svc in sorted(modelo.get("services", {}).items()):
        labels = svc.get("labels") or {}
        for regra, ok, detalhe in regras(nome, svc, redes):
            excecao = labels.get(f"seguranca.excecao.{regra}", "").strip()
            if ok:
                print(f"  PASS     {nome:<10} {regra:<20} {detalhe}")
            elif len(excecao) >= 40:
                print(f"  EXCECAO  {nome:<10} {regra:<20} {excecao[:90]}...")
            else:
                falhas += 1
                motivo = " (excecao sem justificativa suficiente)" if excecao else ""
                print(f"  FAIL     {nome:<10} {regra:<20} esperado: {detalhe}{motivo}")
    return falhas


def main():
    arquivos = sys.argv[1:] or ["docker-compose.yml"]
    falhas = sum(verificar(a) for a in arquivos)
    print(f"\n{falhas} falha(s) de politica.")
    sys.exit(1 if falhas else 0)


if __name__ == "__main__":
    main()
