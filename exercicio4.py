"""Exercício 4 — Transação com trilha de auditoria (Aulas 2, 3 e 8/A09).

A alteração acontece numa transação MySQL (tudo ou nada) e TODA tentativa — aceita,
recusada ou interrompida por erro — vira um documento na coleção Mongo `auditoria`.
"""
from datetime import UTC, datetime

from comum import mongo_db, mysql_conexao

NIVEL_ADMIN = 5
NIVEIS_VALIDOS = range(1, 6)
USUARIOS = [(1, "ana", "ana@x.com", 5), (2, "bruno", "bruno@x.com", 2), (3, "caio", "caio@x.com", 1)]


class Recusa(Exception):
    """Tentativa barrada por regra de negócio (não é erro de sistema)."""


def preparar_banco() -> None:
    with mysql_conexao() as con, con.cursor() as cur:
        cur.execute("DROP TABLE IF EXISTS usuarios")
        cur.execute("""CREATE TABLE usuarios (
                           id           INT PRIMARY KEY,
                           nome         VARCHAR(100) NOT NULL,
                           email        VARCHAR(150) NOT NULL UNIQUE,
                           nivel_acesso TINYINT NOT NULL
                       )""")
        cur.executemany("INSERT INTO usuarios VALUES (%s, %s, %s, %s)", USUARIOS)
        con.commit()


def _nivel_atual(cur, usuario_id: int) -> int | None:
    # FOR UPDATE trava a linha até o fim da transação: ninguém muda o nível no meio da decisão.
    cur.execute("SELECT nivel_acesso FROM usuarios WHERE id = %s FOR UPDATE", (usuario_id,))
    linha = cur.fetchone()
    return linha[0] if linha else None


def _validar(admin_id: int, alvo_id: int, novo_nivel: int, nivel_admin: int | None, nivel_alvo: int | None) -> None:
    if admin_id == alvo_id:
        raise Recusa("auto-promoção")
    if nivel_admin is None or nivel_admin < NIVEL_ADMIN:
        raise Recusa("admin sem privilégio")
    if novo_nivel not in NIVEIS_VALIDOS:
        raise Recusa("nível inválido")
    if nivel_alvo is None:
        raise Recusa("alvo inexistente")


def alterar_nivel(admin_id: int, alvo_id: int, novo_nivel: int) -> tuple[str, str | None]:
    """Devolve (resultado, motivo). Erros inesperados são auditados e depois propagados."""
    registro = {"quem": admin_id, "alvo": alvo_id, "nivel_anterior": None, "nivel_novo": novo_nivel,
                "resultado": "ERRO", "motivo": "falha inesperada"}
    try:
        with mysql_conexao() as con, con.cursor() as cur:
            con.start_transaction()
            try:
                nivel_admin = _nivel_atual(cur, admin_id)
                registro["nivel_anterior"] = nivel_alvo = _nivel_atual(cur, alvo_id)
                _validar(admin_id, alvo_id, novo_nivel, nivel_admin, nivel_alvo)
                cur.execute("UPDATE usuarios SET nivel_acesso = %s WHERE id = %s", (novo_nivel, alvo_id))
                con.commit()
            except BaseException:
                con.rollback()      # qualquer falha desfaz tudo: nada fica gravado pela metade
                raise
        registro.update(resultado="OK", motivo=None)
    except Recusa as recusa:
        registro.update(resultado="RECUSADO", motivo=str(recusa))
    finally:
        # A09: ataque que não deixa rastro é ataque invisível — grava mesmo se a transação falhou.
        mongo_db().auditoria.insert_one({**registro, "timestamp": datetime.now(UTC)})
    return registro["resultado"], registro["motivo"]


def niveis() -> dict[int, tuple[str, int]]:
    with mysql_conexao() as con, con.cursor() as cur:
        cur.execute("SELECT id, nome, nivel_acesso FROM usuarios")
        return {uid: (nome, nivel) for uid, nome, nivel in cur}


def demonstrar(admin_id: int, alvo_id: int, novo_nivel: int) -> None:
    antes = niveis()
    resultado, motivo = alterar_nivel(admin_id, alvo_id, novo_nivel)
    depois = niveis()
    chamada = f"alterar_nivel({admin_id}, {alvo_id}, {novo_nivel})"
    acao = "commit" if resultado == "OK" else "rollback"
    status = resultado if motivo is None else f"{resultado} ({motivo})"
    alvo = ""
    if alvo_id in depois:
        (nome, nivel_final), nivel_inicial = depois[alvo_id], antes[alvo_id][1]
        mudanca = f"{nivel_inicial} -> {nivel_final}" if nivel_inicial != nivel_final else nivel_final
        alvo = f" {nome}: {mudanca}"
    print(f"{chamada:<24}-> {status}. {acao}.{alvo}")


if __name__ == "__main__":
    preparar_banco()
    auditoria = mongo_db().auditoria
    auditoria.delete_many({})   # laboratório: trilha zerada para a demonstração ser reproduzível

    for chamada in [(1, 2, 4), (2, 3, 5), (1, 1, 9), (1, 99, 3)]:
        demonstrar(*chamada)

    sucessos = auditoria.count_documents({"resultado": "OK"})
    recusas = auditoria.count_documents({"resultado": "RECUSADO"})
    print(f"\nTrilha de auditoria ao final: {auditoria.count_documents({})} documentos "
          f"({sucessos} sucesso, {recusas} recusas)")
    print(f'db.auditoria.count_documents({{"resultado": "RECUSADO"}}) -> {recusas}')
