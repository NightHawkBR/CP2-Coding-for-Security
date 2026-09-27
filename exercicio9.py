"""Exercício 9 — Rate limiting guiado por anomalia (Aulas 2, 4, 6 e 8/A09).

Risco de bloquear por anomalia em vez de regra fixa: o modelo não sabe o que é ataque, só o que é
RARO — um pico legítimo (fechamento do mês, uma integração nova) vira falso positivo e derruba usuário
legítimo; e com contamination fixo, ~20% dos IPs são marcados mesmo num dia sem ataque algum.

Mitigações aplicadas: só analisa com população mínima de IPs, só bloqueia quem desvia PARA CIMA
(IP silencioso também é "raro", mas não é ameaça) e o bloqueio expira sozinho (Retry-After).
"""
import math
import threading
import time
from datetime import UTC, datetime, timedelta

import numpy as np
from flask import Flask, g, jsonify, request
from sklearn.ensemble import IsolationForest

from comum import configurar_api, mongo_db

JANELA = timedelta(minutes=10)          # comportamento observado para cada IP
PISO_DURACAO_MS = 10_000                # evita taxa infinita para quem fez 1 requisição agora
MIN_IPS_PARA_ANALISE = 5                # sem população não existe "normal" para comparar
BLOQUEIO_SEGUNDOS = 60
INTERVALO_ANALISE_SEGUNDOS = 30
CONTAMINACAO = 0.2

app = configurar_api(Flask(__name__))
acessos = mongo_db().acessos
bloqueados: dict[str, float] = {}       # ip -> instante (time.monotonic) em que o bloqueio expira


def preparar_indices() -> None:
    acessos.create_index("timestamp", expireAfterSeconds=24 * 3600)   # log de acesso não é eterno
    acessos.create_index([("ip", 1), ("timestamp", 1)])


@app.before_request
def registrar_e_barrar():
    ip = request.remote_addr
    g.acesso_id = acessos.insert_one({
        "ip": ip, "rota": request.path[:200], "metodo": request.method,
        "timestamp": datetime.now(UTC),
    }).inserted_id
    restante = bloqueados.get(ip, 0) - time.monotonic()
    if restante > 0:
        return jsonify(erro="muitas requisições"), 429, {"Retry-After": str(math.ceil(restante))}


@app.after_request
def completar_registro(resposta):
    if (acesso_id := g.get("acesso_id")) is not None:
        acessos.update_one({"_id": acesso_id}, {"$set": {"status": resposta.status_code}})
    return resposta


@app.get("/api/status")
def status():
    return jsonify(status="online")


@app.get("/api/alertas")
def listar_alertas():
    return jsonify([{"id": 1, "tipo": "BRUTE_FORCE", "severidade": "critica"}])


def comportamento_por_ip(agora: datetime | None = None) -> list[dict]:
    """Agregação no banco: [req_por_minuto, taxa_4xx, rotas_distintas] por IP na janela."""
    agora = agora or datetime.now(UTC)
    eh_4xx = {"$and": [{"$gte": ["$status", 400]}, {"$lt": ["$status", 500]}]}
    duracao_minutos = {"$divide": [{"$max": [{"$subtract": [agora, "$primeiro"]}, PISO_DURACAO_MS]}, 60_000]}
    pipeline = [
        {"$match": {"timestamp": {"$gte": agora - JANELA}, "status": {"$exists": True}}},
        {"$group": {"_id": "$ip",
                    "total": {"$sum": 1},
                    "erros_4xx": {"$sum": {"$cond": [eh_4xx, 1, 0]}},
                    "rotas": {"$addToSet": "$rota"},
                    "primeiro": {"$min": "$timestamp"}}},
        {"$project": {"_id": 0, "ip": "$_id",
                      "req_por_minuto": {"$divide": ["$total", duracao_minutos]},
                      "taxa_4xx": {"$divide": ["$erros_4xx", "$total"]},
                      "rotas_distintas": {"$size": "$rotas"}}},
        {"$sort": {"ip": 1}},
    ]
    return list(acessos.aggregate(pipeline))


def analisar_acessos(agora: datetime | None = None) -> list[dict]:
    """Marca anomalias com IsolationForest e bloqueia os IPs anômalos acima do normal."""
    perfis = comportamento_por_ip(agora)
    if len(perfis) < MIN_IPS_PARA_ANALISE:
        return perfis
    X = np.array([[p["req_por_minuto"], p["taxa_4xx"], p["rotas_distintas"]] for p in perfis])
    anomalos = IsolationForest(contamination=CONTAMINACAO, random_state=42).fit_predict(X) == -1
    acima_do_normal = (X > np.median(X, axis=0)).any(axis=1)
    expira = time.monotonic() + BLOQUEIO_SEGUNDOS
    for perfil, anomalo, acima in zip(perfis, anomalos, acima_do_normal):
        perfil["anomalia"] = bool(anomalo)
        perfil["bloqueado"] = bool(anomalo and acima)
        if perfil["bloqueado"]:
            bloqueados[perfil["ip"]] = expira
            app.logger.warning("IP %s bloqueado por %ss: %s", perfil["ip"], BLOQUEIO_SEGUNDOS, perfil)
    return perfis


def imprimir_analise(perfis: list[dict]) -> None:
    print("=== Análise de acessos ===")
    if len(perfis) < MIN_IPS_PARA_ANALISE:
        print(f"Só {len(perfis)} IP(s) na janela: amostra insuficiente, ninguém é bloqueado.")
    for p in perfis:
        if p.get("bloqueado"):
            veredito = "ANOMALIA -> bloqueado"
        elif p.get("anomalia"):
            veredito = "ANOMALIA (abaixo do normal) -> não bloqueado"
        else:
            veredito = "normal"
        print(f"{p['ip']:<15}[{p['req_por_minuto']:6.1f} req/min | 4xx {p['taxa_4xx']:.2f} | "
              f"{p['rotas_distintas']:2d} rotas]  -> {veredito}")


def _analisar_periodicamente() -> None:
    while True:
        time.sleep(INTERVALO_ANALISE_SEGUNDOS)
        try:
            analisar_acessos()
        except Exception:
            app.logger.exception("falha na análise de acessos")


if __name__ == "__main__":
    preparar_indices()
    threading.Thread(target=_analisar_periodicamente, daemon=True).start()
    app.run(host="127.0.0.1", port=5000, debug=False)
