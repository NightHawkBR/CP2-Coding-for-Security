"""Apoio aos testes: sobe um app Flask real numa thread e contabiliza verificações."""
import logging
import sys
import threading
from contextlib import contextmanager
from pathlib import Path

from werkzeug.serving import make_server

# Permite `import exercicioN` rodando `python testes/teste_exN.py` a partir de qualquer pasta.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
logging.getLogger("werkzeug").setLevel(logging.WARNING)


class Verificador:
    def __init__(self, titulo: str):
        self.total = self.falhas = 0
        print(f"=== {titulo} ===")

    def __call__(self, descricao: str, condicao: bool, detalhe: object = "") -> None:
        self.total += 1
        if condicao:
            print(f"  [OK]    {descricao}")
        else:
            self.falhas += 1
            print(f"  [FALHA] {descricao}  {detalhe}")

    def encerrar(self) -> None:
        print(f"\n{self.total - self.falhas}/{self.total} verificações passaram")
        sys.exit(1 if self.falhas else 0)


@contextmanager
def servidor_no_ar(app_wsgi):
    """Servidor HTTP de verdade (porta livre escolhida pelo SO) para testar com `requests`."""
    servidor = make_server("127.0.0.1", 0, app_wsgi, threaded=True)
    threading.Thread(target=servidor.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{servidor.server_port}"
    finally:
        servidor.shutdown()
