import _apoio  # noqa: F401  (ajusta o sys.path)
from _apoio import Verificador
from pymongo.errors import BulkWriteError

import exercicio2 as ex
from comum import mongo_db

v = Verificador("Exercício 2 — migração MySQL -> MongoDB")
ex.preparar_mysql()
v("migração insere 3 documentos", ex.migrar() == 3)

total_mysql, total_mongo, conteudo_igual = ex.verificar_migracao()
v("contagem MySQL == MongoDB == 3", total_mysql == total_mongo == 3, (total_mysql, total_mongo))
v("conteúdo idêntico linha a linha (inclui criado_em)", conteudo_igual)

alertas = mongo_db().alertas
doc = alertas.find_one({"tipo": "BRUTE_FORCE"})
v("ativo aninhado no documento",
  doc["ativo"] == {"nome": "SRV-WEB01", "ip": "192.168.1.10", "criticidade": "alta"}, doc)
v('find({"ativo.criticidade": "alta"}) -> 2 documentos (sem JOIN)',
  alertas.count_documents({"ativo.criticidade": "alta"}) == 2)

v("JOIN incremental respeita o parâmetro (id > 2 -> só o alerta 3)",
  [linha["id"] for linha in ex.ler_alertas_com_ativo(2)] == [3])
# Concatenado, "3 OR 1=1" viraria `id > 3 OR 1=1` (tudo); parametrizado vira o dado '3 OR 1=1' (nada).
v("parâmetro malicioso é tratado como dado, não como SQL", ex.ler_alertas_com_ativo("3 OR 1=1") == [])

try:
    alertas.insert_many(map(ex.para_documento, ex.ler_alertas_com_ativo()))
    v("re-migrar os mesmos ids é barrado (não duplica)", False, "inseriu duplicado")
except BulkWriteError:
    v("re-migrar os mesmos ids é barrado (não duplica)", alertas.count_documents({}) == 3)

v.encerrar()
