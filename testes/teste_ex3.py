import random
from datetime import UTC, datetime, timedelta

import _apoio  # noqa: F401  (ajusta o sys.path)
from _apoio import Verificador

import exercicio3 as ex

v = Verificador("Exercício 3 — TTL e janela temporal")
agora = datetime.now(UTC)
ex.preparar_colecao()
ex.eventos.insert_many(ex.gerar_eventos(agora, random.Random(42)))

v("200 eventos inseridos", ex.eventos.count_documents({}) == 200)
v("todos dentro das últimas 24h",
  ex.eventos.count_documents({"timestamp": {"$gte": agora - timedelta(hours=24), "$lte": agora}}) == 200)

indice = ex.eventos.index_information()["ttl_retencao"]
v("índice TTL de 7 dias em 'timestamp'",
  indice["key"] == [("timestamp", 1)] and indice["expireAfterSeconds"] == 604800, indice)

distribuicao = ex.falhas_por_hora(agora=agora)
total_falhas = ex.eventos.count_documents({"tipo": "FAIL"})
v("soma da agregação por hora == total de falhas", sum(distribuicao.values()) == total_falhas,
  (sum(distribuicao.values()), total_falhas))
v("horas no intervalo 0..23", set(distribuicao) <= set(range(24)), distribuicao)
pico = max(distribuicao, key=distribuicao.get)
v("pico cai na madrugada (padrão gerado)", pico in ex.MADRUGADA, pico)

janela_6h = sum(ex.falhas_por_hora(timedelta(hours=6), agora).values())
esperado_6h = ex.eventos.count_documents({"tipo": "FAIL", "timestamp": {"$gte": agora - timedelta(hours=6)}})
v("janela de 6h confere com contagem direta", janela_6h == esperado_6h, (janela_6h, esperado_6h))

# Evento antigo: está fora da janela (e o TTL o removerá no próximo ciclo de ~60s).
ex.eventos.insert_one({"timestamp": agora - timedelta(days=8), "tipo": "FAIL", "ip": "1.2.3.4"})
v("evento de 8 dias atrás fica fora da janela de 24h",
  sum(ex.falhas_por_hora(agora=agora).values()) == total_falhas)

v.encerrar()
