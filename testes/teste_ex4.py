from contextlib import contextmanager

import _apoio  # noqa: F401  (ajusta o sys.path)
from _apoio import Verificador

import exercicio4 as ex
from comum import mongo_db

v = Verificador("Exercício 4 — transação + trilha de auditoria")
ex.preparar_banco()
auditoria = mongo_db().auditoria
auditoria.delete_many({})

CASOS = [
    ((1, 2, 4), ("OK", None), {2: 4}),
    ((2, 3, 5), ("RECUSADO", "admin sem privilégio"), {3: 1}),
    ((1, 1, 9), ("RECUSADO", "auto-promoção"), {1: 5}),
    ((1, 99, 3), ("RECUSADO", "alvo inexistente"), {}),
]
for args, esperado, niveis_esperados in CASOS:
    obtido = ex.alterar_nivel(*args)
    niveis = {uid: nivel for uid, (_, nivel) in ex.niveis().items()}
    v(f"alterar_nivel{args} -> {esperado}", obtido == esperado, obtido)
    v(f"  níveis após a chamada {niveis_esperados}",
      all(niveis[uid] == n for uid, n in niveis_esperados.items()), niveis)

v("trilha com 4 documentos", auditoria.count_documents({}) == 4)
v('count_documents({"resultado": "RECUSADO"}) -> 3', auditoria.count_documents({"resultado": "RECUSADO"}) == 3)
doc = auditoria.find_one({"resultado": "OK"})
v("documento de sucesso tem quem/alvo/nivel_anterior/nivel_novo/timestamp",
  (doc["quem"], doc["alvo"], doc["nivel_anterior"], doc["nivel_novo"]) == (1, 2, 2, 4) and "timestamp" in doc, doc)

v("nível fora de 1..5 é recusado", ex.alterar_nivel(1, 3, 7) == ("RECUSADO", "nível inválido"))


# Atomicidade: se o commit cair DEPOIS do UPDATE, nada pode ficar gravado — e a tentativa é auditada.
class ConexaoQueCaiNoCommit:
    def __init__(self, real):
        self._real = real

    def __getattr__(self, nome):
        return getattr(self._real, nome)

    def commit(self):
        raise ConnectionError("queda simulada no commit")


conexao_original = ex.mysql_conexao


@contextmanager
def conexao_com_falha():
    with conexao_original() as con:
        yield ConexaoQueCaiNoCommit(con)


ex.mysql_conexao = conexao_com_falha
try:
    ex.alterar_nivel(1, 3, 2)
    v("falha no commit propaga a exceção", False, "não levantou")
except ConnectionError:
    v("falha no commit propaga a exceção", True)
finally:
    ex.mysql_conexao = conexao_original

v("rollback: caio continua no nível 1", ex.niveis()[3][1] == 1, ex.niveis()[3])
v("tentativa interrompida também foi auditada (resultado ERRO)",
  auditoria.count_documents({"resultado": "ERRO", "alvo": 3}) == 1)

v.encerrar()
