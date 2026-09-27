from email.utils import parsedate_to_datetime

import requests

import _apoio  # noqa: F401  (ajusta o sys.path)
from _apoio import Verificador, servidor_no_ar

import exercicio5 as ex
from comum import mysql_conexao

PESO_SEVERIDADE = {"baixa": 0, "media": 1, "alta": 2, "critica": 3}

v = Verificador("Exercício 5 — ORDER BY com whitelist")
ex.preparar_banco()

sql, com_placeholder, com_whitelist = ex.demonstrar_placeholder_no_order_by()
v("driver envia ORDER BY 'severidade' (texto entre aspas, não coluna)", "ORDER BY 'severidade'" in sql, sql)
severidades = [s for _, s in com_placeholder]
v("ORDER BY %s não ordena por severidade",
  severidades != sorted(severidades, key=PESO_SEVERIDADE.get, reverse=True), com_placeholder)

with servidor_no_ar(ex.app) as base:
    def get(query: str) -> requests.Response:
        return requests.get(f"{base}/api/eventos{query}", timeout=5)

    r = get("?ordenar_por=sev&ordem=desc&tamanho=5")
    sevs = [e["severidade"] for e in r.json()]
    v("?ordenar_por=sev&ordem=desc&tamanho=5 -> 200 com 5 eventos", r.status_code == 200 and len(sevs) == 5, r.text)
    v("  ordenados por severidade (critica primeiro)",
      sevs == sorted(sevs, key=PESO_SEVERIDADE.get, reverse=True), sevs)

    r = get("?ordenar_por=criado_em,(SELECT+1)&ordem=asc")
    v("?ordenar_por=criado_em,(SELECT+1) -> 400 campo de ordenação inválido",
      r.status_code == 400 and r.json() == {"erro": "campo de ordenação inválido"}, (r.status_code, r.text))

    r = get("?tamanho=abc")
    v("?tamanho=abc -> 400 tamanho deve ser inteiro",
      r.status_code == 400 and r.json() == {"erro": "tamanho deve ser inteiro"}, (r.status_code, r.text))

    r = get("?tamanho=100000")
    v("?tamanho=100000 -> 200 com no máximo 100 registros",
      r.status_code == 200 and len(r.json()) == 100, (r.status_code, len(r.json())))

    for query in ("?ordem=desc;DROP+TABLE+eventos", "?tamanho=0", "?tamanho=-5", "?ordenar_por=severidade"):
        r = get(query)
        v(f"{query} -> 400", r.status_code == 400, (r.status_code, r.text))

    datas = [parsedate_to_datetime(e["criado_em"]) for e in get("?ordenar_por=data&ordem=asc&tamanho=50").json()]
    v("ordenar_por=data&ordem=asc ordena por criado_em crescente", datas == sorted(datas))
    ips = [e["ip_origem"] for e in get("?ordenar_por=ip&ordem=desc&tamanho=50").json()]
    v("ordenar_por=ip&ordem=desc ordena por ip_origem decrescente", ips == sorted(ips, reverse=True))

    r = get("")
    v("sem parâmetros -> 200 com 20 eventos (padrão)", r.status_code == 200 and len(r.json()) == 20)
    v("headers de segurança presentes (CSP, nosniff, DENY)",
      r.headers.get("Content-Security-Policy") == "default-src 'self'"
      and r.headers.get("X-Content-Type-Options") == "nosniff"
      and r.headers.get("X-Frame-Options") == "DENY", dict(r.headers))

with mysql_conexao() as con, con.cursor() as cur:
    cur.execute("SELECT COUNT(*) FROM eventos")
    v("tabela eventos intacta após as tentativas de injeção", cur.fetchone()[0] == 150)

v.encerrar()
