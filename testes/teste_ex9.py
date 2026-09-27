"""Roteiro de teste do Exercício 9 (script com requests).

Todos os clientes saem do mesmo computador, então cada um informa seu IP no header
X-Forwarded-For e o app é embrulhado em ProxyFix — o papel que um proxy reverso faria.
Isso fica SÓ no teste: o app de verdade não confia nesse header (o atacante poderia forjá-lo).
Além do IP normal e do hostil, quatro usuários de fundo navegam em paralelo: IsolationForest
precisa de população — com só 2 IPs, os dois são isolados na mesma profundidade.
"""
import time
from concurrent.futures import ThreadPoolExecutor

import requests
from werkzeug.middleware.proxy_fix import ProxyFix

import _apoio  # noqa: F401  (ajusta o sys.path)
from _apoio import Verificador, servidor_no_ar

import exercicio9 as ex

IP_NORMAL, IP_HOSTIL = "192.168.1.10", "185.220.101.1"
STATUS, ALERTAS = "/api/status", "/api/alertas"
ROTAS_INEXISTENTES = ["/admin", "/.env", "/wp-login.php", "/phpmyadmin", "/.git/config", "/backup.zip", "/server-status"]

# 60 requisições do hostil: 20 válidas + 40 para 7 rotas inexistentes (9 rotas distintas no total)
ROTEIRO_HOSTIL = [(STATUS, ALERTAS)[i % 2] if i % 3 == 0 else ROTAS_INEXISTENTES[i % 7] for i in range(60)]

CLIENTES = {   # ip -> (rotas, intervalo entre requisições em segundos)
    IP_NORMAL: ([STATUS, ALERTAS, STATUS, ALERTAS, STATUS], 2.5),
    "10.0.0.21": ([STATUS, ALERTAS, ALERTAS, STATUS, STATUS], 2.0),
    "10.0.0.22": ([ALERTAS, STATUS, "/api/alerta", ALERTAS, STATUS, ALERTAS], 2.2),   # 1 erro de digitação
    "10.0.0.23": ([STATUS, STATUS, ALERTAS, STATUS, ALERTAS], 2.8),
    "10.0.0.24": ([ALERTAS, ALERTAS, STATUS, ALERTAS, STATUS], 3.0),
    IP_HOSTIL: (ROTEIRO_HOSTIL, 10 / 60),                                          # 60 req em ~10s
}


def navegar(base: str, ip: str, rotas: list[str], intervalo: float) -> list[int]:
    with requests.Session() as sessao:
        sessao.headers["X-Forwarded-For"] = ip
        codigos = []
        for i, rota in enumerate(rotas):
            if i:
                time.sleep(intervalo)
            codigos.append(sessao.get(base + rota, timeout=5).status_code)
        return codigos


def get_como(base: str, ip: str, rota: str = STATUS) -> requests.Response:
    return requests.get(base + rota, headers={"X-Forwarded-For": ip}, timeout=5)


v = Verificador("Exercício 9 — rate limiting guiado por anomalia")
ex.preparar_indices()
ex.acessos.delete_many({})
ex.bloqueados.clear()
ex.app.wsgi_app = ProxyFix(ex.app.wsgi_app, x_for=1)

with servidor_no_ar(ex.app) as base:
    with ThreadPoolExecutor(max_workers=len(CLIENTES)) as pool:
        futuros = {ip: pool.submit(navegar, base, ip, rotas, intervalo)
                   for ip, (rotas, intervalo) in CLIENTES.items()}
    codigos = {ip: futuro.result() for ip, futuro in futuros.items()}

    v("IP normal: 5 requisições válidas -> todas 200", codigos[IP_NORMAL] == [200] * 5, codigos[IP_NORMAL])
    v("IP hostil: 20 x 200 e 40 x 404 antes da análise",
      (codigos[IP_HOSTIL].count(200), codigos[IP_HOSTIL].count(404)) == (20, 40))

    perfis = ex.analisar_acessos()
    print()
    ex.imprimir_analise(perfis)
    print()
    por_ip = {p["ip"]: p for p in perfis}
    hostil = por_ip[IP_HOSTIL]

    v("agregação trouxe os 6 IPs", set(por_ip) == set(CLIENTES), sorted(por_ip))
    v("hostil: taxa 4xx 0.67 e 9 rotas distintas",
      round(hostil["taxa_4xx"], 2) == 0.67 and hostil["rotas_distintas"] == 9, hostil)
    v("hostil: bem acima de 100 req/min", hostil["req_por_minuto"] > 100, hostil["req_por_minuto"])
    v("hostil marcado como ANOMALIA e bloqueado", hostil.get("bloqueado") is True, hostil)
    v("nenhum IP legítimo bloqueado",
      [ip for ip, p in por_ip.items() if p.get("bloqueado")] == [IP_HOSTIL])

    r = get_como(base, IP_HOSTIL)
    v("próxima requisição do hostil -> 429 {'erro': 'muitas requisições'}",
      r.status_code == 429 and r.json() == {"erro": "muitas requisições"}, (r.status_code, r.text))
    v("  com header Retry-After: 60", r.headers.get("Retry-After") == "60", r.headers.get("Retry-After"))
    v("IP normal continua recebendo 200", get_como(base, IP_NORMAL).status_code == 200)
    v("o 429 também ficou registrado em `acessos` (A09)",
      ex.acessos.count_documents({"ip": IP_HOSTIL, "status": 429}) == 1)
    v("todas as 40 sondagens 404 do hostil ficaram registradas",
      ex.acessos.count_documents({"ip": IP_HOSTIL, "status": 404}) == 40)

    # Com só 2 IPs não existe "normal" para comparar: ninguém deve ser bloqueado.
    ex.acessos.delete_many({})
    ex.bloqueados.clear()
    navegar(base, IP_HOSTIL, ROTEIRO_HOSTIL[:30], 0)
    navegar(base, IP_NORMAL, [STATUS] * 3, 0)
    perfis = ex.analisar_acessos()
    v("com menos de 5 IPs na janela, a análise não bloqueia ninguém",
      len(perfis) == 2 and not ex.bloqueados and get_como(base, IP_HOSTIL).status_code == 200)

v.encerrar()
