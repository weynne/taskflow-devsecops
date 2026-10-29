#!/usr/bin/env python3
"""Simulacao de forca bruta no login da TaskFlow (Modulo 6 - resposta a incidente).

USO EXCLUSIVO em ambiente de laboratorio proprio (localhost). Gera o
incidente que o runbook docs/runbook-login-bruteforce.md manda detectar no
Grafana. Nao usa dependencias externas (so a biblioteca padrao).

Cada tentativa faz o que um atacante faria contra o formulario real: GET
/login para obter o cookie e o token CSRF, depois POST com uma senha da
lista. Opcionalmente, a ultima tentativa usa a senha correta (lida da
variavel de ambiente BRUTEFORCE_SENHA_REAL), simulando um ataque que deu
certo, para exercitar a fase de analise do runbook.

Exemplos:
  python3 scripts/simular-forca-bruta.py
  python3 scripts/simular-forca-bruta.py --usuario admin --tentativas 40
  BRUTEFORCE_SENHA_REAL="$ALUNO_PASSWORD" \\
      python3 scripts/simular-forca-bruta.py --usuario aluno --sucesso-no-fim
"""

import argparse
import http.cookiejar
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SENHAS_COMUNS = [
    "123456", "password", "123456789", "admin", "admin123", "senha", "senha123",
    "qwerty", "12345678", "111111", "abc123", "password1", "iloveyou", "1234",
    "taskflow", "Taskflow1", "welcome", "letmein", "monkey", "dragon",
]
QUERY_DETECCAO = (
    'sum by (client_ip) (count_over_time({service="web", event="login_failure"} | json [5m]))'
)
TOKEN = re.compile(r'name="csrf_token" value="([^"]+)"')


class SemRedirecionamento(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def tentar(alvo, usuario, senha):
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar), SemRedirecionamento()
    )
    # O alvo e informado pelo operador do laboratorio (padrao localhost).
    with opener.open(f"{alvo}/login", timeout=5) as resp:  # noqa: S310
        match = TOKEN.search(resp.read().decode())
    dados = urllib.parse.urlencode(
        {"csrf_token": match.group(1) if match else "", "username": usuario, "password": senha}
    ).encode()
    try:
        with opener.open(f"{alvo}/login", data=dados, timeout=5) as resp:  # noqa: S310
            return resp.status
    except urllib.error.HTTPError as erro:  # 302 (sucesso) chega aqui sem redirect
        return erro.code


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--alvo", default="http://127.0.0.1:5000")
    parser.add_argument("--usuario", default="admin")
    parser.add_argument("--tentativas", type=int, default=30)
    parser.add_argument("--intervalo", type=float, default=0.2, help="segundos entre tentativas")
    parser.add_argument("--sucesso-no-fim", action="store_true",
                        help="ultima tentativa com a senha de BRUTEFORCE_SENHA_REAL")
    args = parser.parse_args()

    if urllib.parse.urlparse(args.alvo).hostname not in ("127.0.0.1", "localhost"):
        sys.exit("Por seguranca, o simulador so ataca 127.0.0.1/localhost.")

    senhas = [SENHAS_COMUNS[i % len(SENHAS_COMUNS)] for i in range(args.tentativas)]
    if args.sucesso_no_fim:
        real = os.environ.get("BRUTEFORCE_SENHA_REAL")
        if not real:
            sys.exit("--sucesso-no-fim exige a variavel BRUTEFORCE_SENHA_REAL.")
        senhas.append(real)

    inicio = time.strftime("%H:%M:%S")
    falhas = sucessos = 0
    for numero, senha in enumerate(senhas, start=1):
        status = tentar(args.alvo, args.usuario, senha)
        if status == 302:
            sucessos += 1
            print(f"[{numero:03d}] SUCESSO para '{args.usuario}'")
        else:
            falhas += 1
            print(f"[{numero:03d}] falhou (HTTP {status})")
        time.sleep(args.intervalo)

    print(f"\nInicio {inicio} | fim {time.strftime('%H:%M:%S')} | "
          f"{falhas} falhas, {sucessos} sucesso(s) contra '{args.usuario}' em {args.alvo}")
    print("No Grafana (Explore > Loki), rode a query de deteccao do runbook:")
    print(f"  {QUERY_DETECCAO}")


if __name__ == "__main__":
    main()
