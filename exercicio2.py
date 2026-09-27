"""Exercício 2 — Migração relacional -> documentos (Aulas 1, 2 e 3).

O que se ganha: o alerta já carrega o ativo embutido — a leitura é uma consulta só, sem JOIN.
O que se perde: os dados do ativo ficam duplicados em cada alerta — renomear o ativo exige update_many.
"""
from datetime import UTC

from comum import mongo_db, mysql_conexao

ATIVOS = [(1, "SRV-WEB01", "192.168.1.10", "alta"), (2, "PC-RH03", "192.168.1.45", "baixa")]
ALERTAS = [(1, 1, "BRUTE_FORCE", "critica"), (2, 1, "PORT_SCAN", "alta"), (3, 2, "XSS", "media")]

DDL = (
    "DROP TABLE IF EXISTS alertas",
    "DROP TABLE IF EXISTS ativos",
    """CREATE TABLE ativos (
           id          INT PRIMARY KEY,
           nome        VARCHAR(100) NOT NULL,
           ip          VARCHAR(45)  NOT NULL UNIQUE,
           criticidade ENUM('baixa','media','alta') NOT NULL
       )""",
    """CREATE TABLE alertas (
           id         INT PRIMARY KEY,
           ativo_id   INT NOT NULL,
           tipo       VARCHAR(50) NOT NULL,
           severidade ENUM('baixa','media','alta','critica') NOT NULL,
           criado_em  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
           FOREIGN KEY (ativo_id) REFERENCES ativos(id)
       )""",
)

# Migração incremental: lê só o que veio depois do último id já migrado.
CONSULTA_JOIN = """
    SELECT al.id, al.tipo, al.severidade, al.criado_em,
           atv.nome, atv.ip, atv.criticidade
      FROM alertas al
      JOIN ativos atv ON atv.id = al.ativo_id
     WHERE al.id > %s
     ORDER BY al.id
"""


def preparar_mysql() -> None:
    """Cria e popula o modelo normalizado (ativos 1—N alertas)."""
    with mysql_conexao() as con, con.cursor() as cur:
        for comando in DDL:
            cur.execute(comando)
        cur.executemany("INSERT INTO ativos (id, nome, ip, criticidade) VALUES (%s, %s, %s, %s)", ATIVOS)
        cur.executemany("INSERT INTO alertas (id, ativo_id, tipo, severidade) VALUES (%s, %s, %s, %s)", ALERTAS)
        con.commit()


def ler_alertas_com_ativo(ultimo_id_migrado: int = 0) -> list[dict]:
    with mysql_conexao() as con, con.cursor(dictionary=True) as cur:
        cur.execute(CONSULTA_JOIN, (ultimo_id_migrado,))
        return cur.fetchall()


def para_documento(linha: dict) -> dict:
    """Desnormaliza: os dados do ativo vão aninhados dentro do alerta."""
    return {
        "_id": linha["id"],   # preserva a identidade da origem: re-migrar não duplica
        "tipo": linha["tipo"],
        "severidade": linha["severidade"],
        "criado_em": linha["criado_em"].replace(tzinfo=UTC),
        "ativo": {"nome": linha["nome"], "ip": linha["ip"], "criticidade": linha["criticidade"]},
    }


def migrar() -> int:
    colecao = mongo_db().alertas
    colecao.drop()
    resultado = colecao.insert_many(map(para_documento, ler_alertas_com_ativo()))
    return len(resultado.inserted_ids)


def verificar_migracao() -> tuple[int, int, bool]:
    """Compara contagem E conteúdo: cada linha do JOIN tem um documento idêntico no Mongo."""
    with mysql_conexao() as con, con.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM alertas")
        (total_mysql,) = cur.fetchone()
    colecao = mongo_db().alertas
    esperado = [para_documento(linha) for linha in ler_alertas_com_ativo()]
    obtido = list(colecao.find().sort("_id"))
    return total_mysql, colecao.count_documents({}), esperado == obtido


if __name__ == "__main__":
    preparar_mysql()
    migrar()
    total_mysql, total_mongo, conteudo_igual = verificar_migracao()
    veredito = "MIGRAÇÃO ÍNTEGRA" if total_mysql == total_mongo and conteudo_igual else "DIVERGÊNCIA!"
    print(f"MySQL: {total_mysql} alertas | MongoDB: {total_mongo} documentos -> {veredito}")

    filtro = {"ativo.criticidade": "alta"}
    print(f"Consulta sem JOIN: db.alertas.find({filtro}) -> "
          f"{mongo_db().alertas.count_documents(filtro)} documentos")
