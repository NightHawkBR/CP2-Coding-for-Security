import requests

import _apoio  # noqa: F401  (ajusta o sys.path)
from _apoio import Verificador, servidor_no_ar

import exercicio6 as ex

ANA, BRUNO = "key-ana-001", "key-bruno-002"

# (método, rota, chave, status esperado) — mesma ordem da matriz do enunciado
MATRIZ = [
    ("GET", "/api/incidentes/1", ANA, 200),
    ("GET", "/api/incidentes/1", BRUNO, 403),       # IDOR barrado
    ("GET", "/api/incidentes/1", None, 401),
    ("GET", "/api/incidentes/1", "key-inexistente", 401),
    ("GET", "/api/incidentes", BRUNO, 200),
    ("DELETE", "/api/incidentes/2", ANA, 200),      # nível 5
    ("DELETE", "/api/incidentes/1", BRUNO, 403),
    ("GET", "/api/incidentes/999", ANA, 404),
]

v = Verificador("Exercício 6 — controle de acesso (A01)")
ex.preparar_banco()

with servidor_no_ar(ex.app) as base:
    def chamar(metodo: str, rota: str, chave: str | None) -> requests.Response:
        headers = {"X-API-Key": chave} if chave else {}
        return requests.request(metodo, base + rota, headers=headers, timeout=5)

    # Antes da matriz (que apaga o incidente 2): o 403 não pode diferenciar "existe" de "não existe".
    existente, inexistente = chamar("GET", "/api/incidentes/1", BRUNO), chamar("GET", "/api/incidentes/999", BRUNO)
    v("bruno: incidente alheio e inexistente recebem o MESMO 403 e o MESMO corpo",
      (existente.status_code, existente.json()) == (inexistente.status_code, inexistente.json()) == (403, {"erro": "acesso negado"}),
      (existente.text, inexistente.text))
    v("ana (nível 5) também não lê incidente do bruno -> 403",
      chamar("GET", "/api/incidentes/2", ANA).status_code == 403)

    for metodo, rota, chave, esperado in MATRIZ:
        r = chamar(metodo, rota, chave)
        v(f"{metodo:<6} {rota:<21} {str(chave):<16} -> {esperado}", r.status_code == esperado, (r.status_code, r.text))
        if (metodo, rota, chave) == ("GET", "/api/incidentes", BRUNO):
            v("  lista do bruno traz só o incidente 2", [i["id"] for i in r.json()] == [2], r.json())
        if esperado == 401:
            v("  401 traz WWW-Authenticate", "WWW-Authenticate" in r.headers)

    v("DELETE do bruno não apagou nada: ana ainda lê o incidente 1",
      chamar("GET", "/api/incidentes/1", ANA).status_code == 200)
    v("incidente 2 foi mesmo removido: ana recebe 404 ao apagar de novo",
      chamar("DELETE", "/api/incidentes/2", ANA).status_code == 404)
    v("bruno DELETE em id inexistente -> 403 (não revela inexistência)",
      chamar("DELETE", "/api/incidentes/999", BRUNO).status_code == 403)
    v("SQL injection na API key -> 401", chamar("GET", "/api/incidentes", "' OR '1'='1").status_code == 401)

v.encerrar()
