"""Exercício 7 — XSS onde ninguém procura: dentro do atributo (Aulas 6, 7 e 8/A05).

Defesa: template Jinja2 com escape automático. Ele converte < > & " ' em entidades, então
o payload não fecha a tag nem sai do atributo — desde que o atributo esteja entre ASPAS.
Por que um |safe mal colocado reabriria o buraco: |safe marca o texto como HTML confiável e
desliga o escape naquele ponto, e o título que veio do banco (ou seja, do usuário) volta a ser marcação.
CSP `default-src 'self'` é a segunda camada: mesmo que algo escape, script inline não executa.
"""
from datetime import UTC, datetime

from flask import Flask, jsonify, render_template_string, request

from comum import configurar_api, mongo_db

P1 = "<script>alert('xss1')</script>"
P2 = 'x" onerror="alert(\'xss2\')'      # escapa do atributo, sem usar <script>
SEVERIDADES = {"baixa", "media", "alta", "critica"}
TAMANHO_MAXIMO_TEXTO = 200

TEMPLATE_DASHBOARD = """<!doctype html>
<html lang="pt-br">
<head><meta charset="utf-8"><title>Dashboard de incidentes</title></head>
<body>
  <h1>Incidentes</h1>
  <table>
    <tr><th>Título</th><th>Ativo</th><th>Severidade</th></tr>
    {% for inc in incidentes %}
    <tr>
      <td>{{ inc.titulo }}</td>
      <td><img src="/icone.png" alt="{{ inc.ativo }}"> {{ inc.ativo }}</td>
      <td>{{ inc.severidade }}</td>
    </tr>
    {% endfor %}
  </table>
</body>
</html>"""

app = configurar_api(Flask(__name__))
incidentes = mongo_db().incidentes


def _listar() -> list[dict]:
    return list(incidentes.find({}, {"_id": 0}).sort("criado_em", 1))


@app.post("/api/incidentes")
def cadastrar_incidente():
    """Guarda o texto como veio (é dado); a proteção acontece na SAÍDA, ao renderizar."""
    dados = request.get_json(silent=True) or {}
    campos = {nome: dados.get(nome) for nome in ("titulo", "ativo", "severidade")}
    if not all(isinstance(valor, str) and 0 < len(valor) <= TAMANHO_MAXIMO_TEXTO for valor in campos.values()):
        return jsonify(erro=f"titulo, ativo e severidade: texto de 1 a {TAMANHO_MAXIMO_TEXTO} caracteres"), 400
    if campos["severidade"] not in SEVERIDADES:
        return jsonify(erro="severidade inválida"), 400
    resultado = incidentes.insert_one({**campos, "criado_em": datetime.now(UTC)})
    return jsonify(id=str(resultado.inserted_id)), 201


@app.get("/dashboard")
def dashboard():
    return render_template_string(TEMPLATE_DASHBOARD, incidentes=_listar())


@app.get("/dashboard-inseguro")
def dashboard_inseguro():
    """⚠️ VULNERÁVEL DE PROPÓSITO — só para comparação no laboratório.

    Monta o HTML por concatenação, sem escape: P1 vira <script> de verdade e P2 fecha o
    atributo alt e cria um onerror. Só não executa porque o CSP bloqueia script inline.
    """
    linhas = "".join(
        f'<tr><td>{inc["titulo"]}</td>'
        f'<td><img src="/icone.png" alt="{inc["ativo"]}"> {inc["ativo"]}</td>'
        f'<td>{inc["severidade"]}</td></tr>'
        for inc in _listar()
    )
    return ('<!doctype html><html lang="pt-br"><head><meta charset="utf-8">'
            "<title>INSEGURO</title></head><body>"
            "<h1>⚠️ PÁGINA INSEGURA — apenas laboratório</h1>"
            f"<table><tr><th>Título</th><th>Ativo</th><th>Severidade</th></tr>{linhas}</table>"
            "</body></html>")


def popular() -> None:
    """Laboratório: recria a coleção com os dois payloads (cada um no título E no atributo)."""
    incidentes.drop()
    incidentes.insert_many([
        {"titulo": payload, "ativo": payload, "severidade": "alta", "criado_em": datetime.now(UTC)}
        for payload in (P1, P2)
    ])


if __name__ == "__main__":
    popular()
    print("Compare: http://127.0.0.1:5000/dashboard  x  http://127.0.0.1:5000/dashboard-inseguro")
    app.run(host="127.0.0.1", port=5000, debug=False)
