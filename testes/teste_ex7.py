from html.parser import HTMLParser

import requests

import _apoio  # noqa: F401  (ajusta o sys.path)
from _apoio import Verificador, servidor_no_ar

import exercicio7 as ex


class AnalisadorHTML(HTMLParser):
    """Lê a página como um navegador leria: o que vira TAG e o que fica como TEXTO."""

    def __init__(self, html: str):
        super().__init__()
        self.scripts, self.imgs, self.textos = 0, [], []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.scripts += tag == "script"
        if tag == "img":
            self.imgs.append(dict(attrs))

    def handle_data(self, data):
        self.textos.append(data)


v = Verificador("Exercício 7 — XSS em conteúdo e em atributo")
ex.incidentes.drop()
CSP = "default-src 'self'"

with servidor_no_ar(ex.app) as base:
    for payload in (ex.P1, ex.P2):
        r = requests.post(f"{base}/api/incidentes", timeout=5,
                          json={"titulo": payload, "ativo": payload, "severidade": "alta"})
        v(f"cadastro com payload {payload!r} -> 201", r.status_code == 201, r.text)

    for descricao, corpo in [
        ("sem campos", {}),
        ("severidade inválida", {"titulo": "t", "ativo": "a", "severidade": "urgente"}),
        ("título não-texto", {"titulo": 123, "ativo": "a", "severidade": "alta"}),
        ("título gigante", {"titulo": "x" * 500, "ativo": "a", "severidade": "alta"}),
    ]:
        r = requests.post(f"{base}/api/incidentes", json=corpo, timeout=5)
        v(f"cadastro com {descricao} -> 400", r.status_code == 400, (r.status_code, r.text))

    r = requests.get(f"{base}/dashboard", timeout=5)
    pagina = AnalisadorHTML(r.text)
    v("/dashboard -> 200 com CSP", r.status_code == 200 and r.headers.get("Content-Security-Policy") == CSP)
    v("/dashboard: nenhuma tag <script> foi criada", pagina.scripts == 0, r.text)
    v("/dashboard: nenhum <img> ganhou atributo on*",
      not any(nome.startswith("on") for img in pagina.imgs for nome in img), pagina.imgs)
    v("/dashboard: P1 e P2 ficaram INTEIROS dentro do alt, como texto",
      [img.get("alt") for img in pagina.imgs] == [ex.P1, ex.P2], pagina.imgs)
    texto = "".join(pagina.textos)
    v("/dashboard: P1 e P2 aparecem como texto literal nas células", ex.P1 in texto and ex.P2 in texto)
    v("/dashboard: HTML traz entidades escapadas (&lt;script&gt; e &#34;)",
      "&lt;script&gt;" in r.text and "x&#34; onerror=&#34;" in r.text)

    r = requests.get(f"{base}/dashboard-inseguro", timeout=5)
    inseguro = AnalisadorHTML(r.text)
    v("/dashboard-inseguro: P1 vira <script> de verdade (vulnerável)", inseguro.scripts >= 1)
    v("/dashboard-inseguro: P2 sai do alt e cria onerror (vulnerável)",
      any("onerror" in img for img in inseguro.imgs), inseguro.imgs)
    v("/dashboard-inseguro: mesmo assim recebe CSP (2ª camada bloqueia a execução)",
      r.headers.get("Content-Security-Policy") == CSP)

    r = requests.get(f"{base}/rota-que-nao-existe", timeout=5)
    v("CSP também em respostas de erro (404)",
      r.status_code == 404 and r.headers.get("Content-Security-Policy") == CSP)

v.encerrar()
