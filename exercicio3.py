"""Exercício 3 — Retenção e janela temporal (Aula 2).

Por que o TTL é decisão de segurança: ele define por quanto tempo a evidência existe — curto demais
apaga o rastro antes da investigação (A09), longo demais guarda dado pessoal além do necessário e
aumenta o que vaza numa invasão (LGPD, minimização).
"""
import random
from datetime import UTC, datetime, timedelta

from comum import mongo_db

RETENCAO_SEGUNDOS = 7 * 24 * 3600          # 7 dias
TOTAL_EVENTOS = 200
FUSO_LOCAL = datetime.now().astimezone().strftime("%z")   # ex.: "-0300", aceito pelo $hour
PESO_POR_HORA = {1: 4, 2: 7, 3: 9, 4: 5}   # madrugada concentra o ataque automatizado
MADRUGADA = PESO_POR_HORA.keys()
IPS_ATACANTES = ("185.220.101.1", "91.240.118.172", "45.33.32.156")
IPS_INTERNOS = ("192.168.1.10", "192.168.1.45", "10.0.0.7")

eventos = mongo_db().eventos


def preparar_colecao() -> None:
    eventos.drop()
    eventos.create_index("timestamp", expireAfterSeconds=RETENCAO_SEGUNDOS, name="ttl_retencao")


def gerar_eventos(agora: datetime, rng: random.Random):
    """Eventos espalhados nas últimas 24h, com mais falhas na madrugada."""
    minutos = [agora - timedelta(minutes=m) for m in range(1, 24 * 60)]
    pesos = [PESO_POR_HORA.get(instante.astimezone().hour, 1) for instante in minutos]
    for instante in rng.choices(minutos, weights=pesos, k=TOTAL_EVENTOS):
        madrugada = instante.astimezone().hour in MADRUGADA
        falha = rng.random() < (0.85 if madrugada else 0.25)
        yield {
            "timestamp": instante - timedelta(seconds=rng.randrange(60)),
            "fonte": "auth",
            "tipo": "FAIL" if falha else "SUCCESS",
            "ip": rng.choice(IPS_ATACANTES if falha else IPS_INTERNOS),
        }


def falhas_por_hora(janela: timedelta = timedelta(hours=24), agora: datetime | None = None) -> dict[int, int]:
    """Agregação no banco: {hora_local: total_de_falhas} dentro da janela."""
    agora = agora or datetime.now(UTC)
    pipeline = [
        {"$match": {"tipo": "FAIL", "timestamp": {"$gte": agora - janela}}},
        {"$group": {"_id": {"$hour": {"date": "$timestamp", "timezone": FUSO_LOCAL}},
                    "total": {"$sum": 1}}},
        {"$sort": {"_id": 1}},
    ]
    return {doc["_id"]: doc["total"] for doc in eventos.aggregate(pipeline)}


def imprimir_histograma(distribuicao: dict[int, int], largura: int = 40) -> None:
    hora_pico, total_pico = max(distribuicao.items(), key=lambda item: item[1])
    print("=== Falhas por hora (últimas 24h) ===")
    for hora, total in distribuicao.items():
        barra = "█" * max(1, round(total * largura / total_pico))
        marca = "   <- pico" if hora == hora_pico else ""
        print(f"{hora:02d}h | {barra} {total}{marca}")
    print(f"Hora de pico: {hora_pico:02d}h ({total_pico} falhas)")


if __name__ == "__main__":
    preparar_colecao()
    eventos.insert_many(gerar_eventos(datetime.now(UTC), random.Random(42)))

    imprimir_histograma(falhas_por_hora())
    print(f"Últimas 6h: {sum(falhas_por_hora(timedelta(hours=6)).values())} falhas")

    ttl = eventos.index_information()["ttl_retencao"]["expireAfterSeconds"]
    print(f"Índice TTL ativo: eventos com mais de {ttl // 86400} dias serão removidos automaticamente.")
