import requests

import _apoio  # noqa: F401  (ajusta o sys.path)
from _apoio import Verificador, servidor_no_ar

import exercicio8 as ex
from comum import mongo_db

v = Verificador("Exercício 8 — modelo de ML servido por API")
previsoes = mongo_db().previsoes
previsoes.delete_many({})   # laboratório: começa com a trilha vazia

with servidor_no_ar(ex.app) as base:
    def triagem(**kwargs) -> requests.Response:
        return requests.post(f"{base}/api/triagem", timeout=5, **kwargs)

    r = triagem(json={"features": [12, 7, 90000, 3]})
    v("[12,7,90000,3] -> 200 risco alto com confiança >= 0.9",
      r.status_code == 200 and r.json()["risco"] == "alto" and r.json()["confianca"] >= 0.9, r.text)
    r = triagem(json={"features": [0, 1, 1200, 14]})
    v("[0,1,1200,14] -> 200 risco baixo com confiança >= 0.9",
      r.status_code == 200 and r.json()["risco"] == "baixo" and r.json()["confianca"] >= 0.9, r.text)

    for descricao, kwargs, erro in [
        ("[12,7,90000]", {"json": {"features": [12, 7, 90000]}}, "esperadas 4 features, recebidas 3"),
        ('["12","sete",0,3]', {"json": {"features": ["12", "sete", 0, 3]}}, "features devem ser numéricas"),
        ("{} (sem features)", {"json": {}}, None),
        ("sem corpo", {}, None),
        ("JSON quebrado", {"data": "{features:", "headers": {"Content-Type": "application/json"}}, None),
        ("booleanos", {"json": {"features": [True, 1, 1, 1]}}, "features devem ser numéricas"),
        # corpo cru: o `requests` se recusa a serializar NaN, mas um atacante não usa o `requests`
        ("NaN", {"data": '{"features": [NaN, 1, 1, 1]}', "headers": {"Content-Type": "application/json"}},
         "features devem ser numéricas"),
        ("Infinity", {"data": '{"features": [1, 1, Infinity, 1]}', "headers": {"Content-Type": "application/json"}},
         "features devem ser numéricas"),
        ("hora 25", {"json": {"features": [1, 1, 1, 25]}}, None),
        ("bytes negativos", {"json": {"features": [1, 1, -5, 3]}}, None),
        ("features não-lista", {"json": {"features": "12,7,90000,3"}}, None),
    ]:
        r = triagem(**kwargs)
        ok = r.status_code == 400 and (erro is None or r.json() == {"erro": erro})
        v(f"{descricao} -> 400" + (f" '{erro}'" if erro else ""), ok, (r.status_code, r.text))

    r = triagem(data="x" * 5000, headers={"Content-Type": "application/json"})
    v("corpo acima de 1 KB -> 413", r.status_code == 413, (r.status_code, r.text))

    r = requests.get(f"{base}/api/modelo/metricas", timeout=5)
    m = r.json()
    v("GET /api/modelo/metricas -> 200 com precisao, recall, f1, matriz e aviso",
      r.status_code == 200 and {"precisao", "recall", "f1", "matriz", "aviso"} <= set(m), m)
    v("  métricas entre 0 e 1", all(0 <= m[k] <= 1 for k in ("precisao", "recall", "f1")))
    v("  matriz 2x2 soma o total do conjunto de teste",
      len(m["matriz"]) == 2 and sum(map(sum, m["matriz"])) == m["amostras_teste"], m["matriz"])
    v("  acurácia omitida de propósito", not any("acur" in chave for chave in m) and "Acurácia" in m["aviso"])

v("db.previsoes.count_documents({}) -> 2 (só as válidas)", previsoes.count_documents({}) == 2,
  previsoes.count_documents({}))
doc = previsoes.find_one({"risco": "alto"})
v("previsão gravada com entrada, saída, confiança e timestamp",
  doc["entrada"] == {"falhas_login": 12, "portas_distintas": 7, "bytes_saida": 90000, "hora_do_dia": 3}
  and {"confianca", "timestamp"} <= set(doc), doc)

v.encerrar()
