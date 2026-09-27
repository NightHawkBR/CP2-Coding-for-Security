"""Exercício 8 — Modelo de ML servido por API, com métricas auditáveis (Aulas 2, 4, 6 e 7).

Entrada de modelo também é entrada de usuário: tipo, quantidade, finitude e faixa de cada
feature são validados antes de chegar ao predict. Toda previsão válida vai para a coleção
`previsoes` (entrada, saída, confiança, timestamp) para auditar o modelo depois (A09/A08).
"""
import math
from datetime import UTC, datetime

import numpy as np
from flask import Flask, jsonify, request
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from comum import configurar_api, mongo_db

FEATURES = ("falhas_login", "portas_distintas", "bytes_saida", "hora_do_dia")
LIMITES = {"falhas_login": (0, 10**6), "portas_distintas": (0, 65535),
           "bytes_saida": (0, 10**15), "hora_do_dia": (0, 23)}
ROTULOS = {0: "baixo", 1: "alto"}
AVISO = ("Acurácia omitida de propósito: ameaças são minoria, e um modelo que sempre responde "
         "'baixo' teria acurácia alta com recall zero — precisão, recall e F1 mostram o que "
         "importa num SOC: quantos alarmes são falsos e quantos ataques passam.")


class EntradaInvalida(ValueError):
    """Corpo da requisição fora do contrato -> 400."""


def gerar_dataset(n: int = 400, semente: int = 42) -> tuple[np.ndarray, np.ndarray]:
    """Dados sintéticos com sobreposição realista (plantão noturno, ataque em horário comercial)."""
    rng = np.random.default_rng(semente)
    n_risco = n // 4                     # ameaça é minoria, como num SOC real
    n_normal = n - n_risco
    normal = np.column_stack([
        rng.poisson(1, n_normal),                                    # erro de digitação ocasional
        rng.integers(1, 4, n_normal),                                # poucas portas
        rng.lognormal(8, 1, n_normal),                               # ~3 KB de saída
        np.where(rng.random(n_normal) < 0.15,                        # 15% em plantão
                 rng.integers(0, 24, n_normal), rng.integers(8, 19, n_normal)),
    ])
    risco = np.column_stack([
        rng.poisson(10, n_risco),                                    # brute force
        rng.integers(3, 30, n_risco),                                # varredura de portas
        rng.lognormal(10.5, 1, n_risco),                             # exfiltração (~36 KB+)
        np.where(rng.random(n_risco) < 0.3,                          # 30% em horário comercial
                 rng.integers(8, 19, n_risco), rng.choice([0, 1, 2, 3, 4, 5, 22, 23], n_risco)),
    ])
    X = np.vstack([normal, risco])
    y = np.concatenate([np.zeros(n_normal, dtype=int), np.ones(n_risco, dtype=int)])
    return X, y


def treinar() -> tuple[RandomForestClassifier, dict]:
    X, y = gerar_dataset()
    X_treino, X_teste, y_treino, y_teste = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y)
    modelo = RandomForestClassifier(n_estimators=100, random_state=42).fit(X_treino, y_treino)
    previsto = modelo.predict(X_teste)
    metricas = {
        "precisao": round(float(precision_score(y_teste, previsto)), 2),
        "recall": round(float(recall_score(y_teste, previsto)), 2),
        "f1": round(float(f1_score(y_teste, previsto)), 2),
        "matriz": confusion_matrix(y_teste, previsto).tolist(),   # [[VN, FP], [FN, VP]]
        "amostras_teste": len(y_teste),
        "aviso": AVISO,
    }
    return modelo, metricas


def _eh_numero(valor) -> bool:
    # bool é subclasse de int em Python: True não é uma contagem de falhas.
    return isinstance(valor, (int, float)) and not isinstance(valor, bool) and math.isfinite(valor)


def validar_features(corpo) -> list[float]:
    if not isinstance(corpo, dict) or "features" not in corpo:
        raise EntradaInvalida("corpo JSON com o campo 'features' é obrigatório")
    features = corpo["features"]
    if not isinstance(features, list):
        raise EntradaInvalida("'features' deve ser uma lista")
    if len(features) != len(FEATURES):
        raise EntradaInvalida(f"esperadas {len(FEATURES)} features, recebidas {len(features)}")
    if not all(map(_eh_numero, features)):
        raise EntradaInvalida("features devem ser numéricas")
    for nome, valor in zip(FEATURES, features):
        minimo, maximo = LIMITES[nome]
        if not minimo <= valor <= maximo:
            raise EntradaInvalida(f"{nome} deve estar entre {minimo} e {maximo}")
    return features


MODELO, METRICAS = treinar()
app = configurar_api(Flask(__name__))
app.config["MAX_CONTENT_LENGTH"] = 1024   # 4 números não precisam de mais que 1 KB


@app.errorhandler(EntradaInvalida)
def _entrada_invalida(erro):
    return jsonify(erro=str(erro)), 400


@app.post("/api/triagem")
def triagem():
    features = validar_features(request.get_json(silent=True))
    probabilidades = MODELO.predict_proba([features])[0]
    indice = int(probabilidades.argmax())
    resposta = {"risco": ROTULOS[int(MODELO.classes_[indice])],
                "confianca": round(float(probabilidades[indice]), 2)}
    mongo_db().previsoes.insert_one({
        "entrada": dict(zip(FEATURES, features)), **resposta,
        "ip": request.remote_addr, "timestamp": datetime.now(UTC),
    })
    return jsonify(resposta)


@app.get("/api/modelo/metricas")
def metricas():
    return jsonify(METRICAS)


if __name__ == "__main__":
    m = METRICAS
    print(f"Modelo treinado — teste com {m['amostras_teste']} amostras: precisão {m['precisao']} | "
          f"recall {m['recall']} | F1 {m['f1']} | matriz {m['matriz']}")
    app.run(host="127.0.0.1", port=5000, debug=False)
