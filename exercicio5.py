"""Exercício 5 — O ORDER BY que o %s não protege (Aulas 3, 6, 7 e 8/A05).

Por que `LIMIT %s` funciona mas `ORDER BY %s` não:
  LIMIT recebe um VALOR: o driver envia 5 como literal numérico — dado é o que o placeholder protege.
  ORDER BY recebe um IDENTIFICADOR: o driver envia 'severidade' entre aspas e o MySQL ordena por uma constante.
  Placeholder separa dado de código; nome de coluna É código, então só entra por whitelist fechada.
"""
import random
from datetime import UTC, datetime, timedelta

from flask import Flask, jsonify, request

from comum import configurar_api, mysql_conexao

COLUNAS = {"data": "criado_em", "sev": "severidade", "ip": "ip_origem"}
ORDEM = {"asc": "ASC", "desc": "DESC"}
TAMANHO_PADRAO, TAMANHO_MAXIMO = 20, 100

TIPOS = ("BRUTE_FORCE", "PORT_SCAN", "XSS", "SQLI")
SEVERIDADES = ("baixa", "media", "alta", "critica")
IPS = ("185.220.101.1", "45.33.32.156", "91.240.118.172", "192.168.1.10", "10.0.0.7")

app = configurar_api(Flask(__name__))


class ParametroInvalido(ValueError):
    """Query string fora do contrato da API -> 400."""


@app.errorhandler(ParametroInvalido)
def _parametro_invalido(erro):
    return jsonify(erro=str(erro)), 400


def ler_parametros(args) -> tuple[str, str, int]:
    try:
        coluna = COLUNAS[args.get("ordenar_por", "data")]
    except KeyError:
        raise ParametroInvalido("campo de ordenação inválido") from None
    try:
        direcao = ORDEM[args.get("ordem", "desc").lower()]
    except KeyError:
        raise ParametroInvalido("ordem deve ser 'asc' ou 'desc'") from None
    try:
        tamanho = int(args.get("tamanho", TAMANHO_PADRAO))
    except ValueError:
        raise ParametroInvalido("tamanho deve ser inteiro") from None
    if tamanho < 1:
        raise ParametroInvalido("tamanho deve ser positivo")
    return coluna, direcao, min(tamanho, TAMANHO_MAXIMO)   # teto do servidor


@app.get("/api/eventos")
def listar_eventos():
    coluna, direcao, tamanho = ler_parametros(request.args)
    # Seguro: `coluna` e `direcao` só podem ser VALORES dos dicionários acima, nunca texto do
    # usuário. O dado variável (tamanho) continua parametrizado.
    sql = ("SELECT id, tipo, severidade, ip_origem, criado_em FROM eventos "
           f"ORDER BY {coluna} {direcao}, id {direcao} LIMIT %s")
    with mysql_conexao() as con, con.cursor(dictionary=True) as cur:
        cur.execute(sql, (tamanho,))
        return jsonify(cur.fetchall())


def preparar_banco(total: int = 150, semente: int = 42) -> None:
    rng = random.Random(semente)
    agora = datetime.now(UTC).replace(tzinfo=None, microsecond=0)
    linhas = [(rng.choice(TIPOS), rng.choice(SEVERIDADES), rng.choice(IPS),
               agora - timedelta(minutes=rng.randrange(7 * 24 * 60)))
              for _ in range(total)]
    with mysql_conexao() as con, con.cursor() as cur:
        cur.execute("DROP TABLE IF EXISTS eventos")
        cur.execute("""CREATE TABLE eventos (
                           id         INT AUTO_INCREMENT PRIMARY KEY,
                           tipo       VARCHAR(50) NOT NULL,
                           severidade ENUM('baixa','media','alta','critica') NOT NULL,
                           ip_origem  VARCHAR(45) NOT NULL,
                           criado_em  DATETIME NOT NULL
                       )""")
        cur.executemany("INSERT INTO eventos (tipo, severidade, ip_origem, criado_em) "
                        "VALUES (%s, %s, %s, %s)", linhas)
        con.commit()


def demonstrar_placeholder_no_order_by() -> tuple[str, list, list]:
    """Prova prática: com ORDER BY %s o MySQL recebe um texto constante e não ordena nada."""
    with mysql_conexao() as con, con.cursor() as cur:
        cur.execute("SELECT id, severidade FROM eventos ORDER BY %s DESC LIMIT 5", ("severidade",))
        com_placeholder, sql_enviado = cur.fetchall(), cur.statement
        cur.execute("SELECT id, severidade FROM eventos ORDER BY severidade DESC, id DESC LIMIT 5")
        com_whitelist = cur.fetchall()
    return sql_enviado, com_placeholder, com_whitelist


if __name__ == "__main__":
    preparar_banco()
    sql_enviado, com_placeholder, com_whitelist = demonstrar_placeholder_no_order_by()
    print(f"SQL que o driver enviou: {sql_enviado}")
    print(f"  ORDER BY %s    -> {com_placeholder}   (não ordenou)")
    print(f"  via whitelist  -> {com_whitelist}")
    app.run(host="127.0.0.1", port=5000, debug=False)
