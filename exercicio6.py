"""Exercício 6 — Controle de acesso quebrado (Aulas 3, 6 e 8/A01).

401 = "não sei quem você é"; 403 = "sei quem você é e você não pode".
Para quem não tem visão global, "não existe" e "não é seu" recebem o MESMO 403 com o
mesmo corpo — assim o status não vira um oráculo para descobrir quais ids existem.
As API keys são guardadas como hash SHA-256: um vazamento do banco não entrega as chaves.
"""
import hashlib
from functools import wraps

from flask import Flask, g, jsonify, request

from comum import configurar_api, mysql_conexao

NIVEL_GLOBAL = 5    # quem pode apagar qualquer incidente (e, portanto, saber se um id existe)
ANALISTAS = [(1, "ana", "key-ana-001", 5), (2, "bruno", "key-bruno-002", 2)]
INCIDENTES = [(1, 1, "Brute force SSH", "critica"), (2, 2, "Phishing no RH", "media")]

app = configurar_api(Flask(__name__))


def hash_chave(chave: str) -> str:
    return hashlib.sha256(chave.encode()).hexdigest()


def _analista_por_chave(chave: str) -> dict | None:
    with mysql_conexao() as con, con.cursor(dictionary=True) as cur:
        cur.execute("SELECT id, nome, nivel FROM analistas WHERE api_key_hash = %s", (hash_chave(chave),))
        return cur.fetchone()


def requer_analista(view):
    """Autentica pelo header X-API-Key e deixa o analista em `g.analista`."""
    @wraps(view)
    def protegida(*args, **kwargs):
        chave = request.headers.get("X-API-Key", "")
        g.analista = _analista_por_chave(chave) if chave else None
        if g.analista is None:
            app.logger.warning("401 %s %s de %s", request.method, request.path, request.remote_addr)
            return (jsonify(erro="credencial ausente ou inválida"), 401,
                    {"WWW-Authenticate": 'ApiKey header="X-API-Key"'})
        return view(*args, **kwargs)
    return protegida


def _recusar(incidente: dict | None):
    """403 genérico; só quem tem visão global recebe 404 para id inexistente."""
    if incidente is None and g.analista["nivel"] >= NIVEL_GLOBAL:
        return jsonify(erro="incidente não encontrado"), 404
    app.logger.warning("403 %s %s para analista %s", request.method, request.path, g.analista["id"])
    return jsonify(erro="acesso negado"), 403


@app.get("/api/incidentes")
@requer_analista
def listar_incidentes():
    with mysql_conexao() as con, con.cursor(dictionary=True) as cur:
        cur.execute("SELECT id, titulo, severidade, status FROM incidentes WHERE dono_id = %s ORDER BY id",
                    (g.analista["id"],))
        return jsonify(cur.fetchall())


@app.get("/api/incidentes/<int:incidente_id>")
@requer_analista
def obter_incidente(incidente_id: int):
    with mysql_conexao() as con, con.cursor(dictionary=True) as cur:
        cur.execute("SELECT id, dono_id, titulo, severidade, status FROM incidentes WHERE id = %s",
                    (incidente_id,))
        incidente = cur.fetchone()
    if incidente and incidente["dono_id"] == g.analista["id"]:
        return jsonify(incidente)
    return _recusar(incidente)


@app.delete("/api/incidentes/<int:incidente_id>")
@requer_analista
def remover_incidente(incidente_id: int):
    if g.analista["nivel"] < NIVEL_GLOBAL:
        return _recusar(None)   # nega sem nem consultar: a resposta não depende do id existir
    with mysql_conexao() as con, con.cursor() as cur:
        cur.execute("DELETE FROM incidentes WHERE id = %s", (incidente_id,))
        con.commit()
        if cur.rowcount == 0:
            return _recusar(None)
    app.logger.info("incidente %s removido pelo analista %s", incidente_id, g.analista["id"])
    return jsonify(mensagem="Removido", id=incidente_id)


def preparar_banco() -> None:
    with mysql_conexao() as con, con.cursor() as cur:
        cur.execute("DROP TABLE IF EXISTS incidentes")
        cur.execute("DROP TABLE IF EXISTS analistas")
        cur.execute("""CREATE TABLE analistas (
                           id           INT PRIMARY KEY,
                           nome         VARCHAR(100) NOT NULL,
                           api_key_hash CHAR(64) NOT NULL UNIQUE,
                           nivel        TINYINT NOT NULL
                       )""")
        cur.execute("""CREATE TABLE incidentes (
                           id         INT AUTO_INCREMENT PRIMARY KEY,
                           dono_id    INT NOT NULL,
                           titulo     VARCHAR(200) NOT NULL,
                           severidade ENUM('baixa','media','alta','critica') NOT NULL,
                           status     VARCHAR(20) NOT NULL DEFAULT 'aberto',
                           FOREIGN KEY (dono_id) REFERENCES analistas(id)
                       )""")
        cur.executemany("INSERT INTO analistas VALUES (%s, %s, %s, %s)",
                        [(aid, nome, hash_chave(chave), nivel) for aid, nome, chave, nivel in ANALISTAS])
        cur.executemany("INSERT INTO incidentes (id, dono_id, titulo, severidade) VALUES (%s, %s, %s, %s)",
                        INCIDENTES)
        con.commit()


if __name__ == "__main__":
    preparar_banco()
    app.run(host="127.0.0.1", port=5000, debug=False)
