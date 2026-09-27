import _apoio  # noqa: F401  (ajusta o sys.path)
from _apoio import Verificador

from exercicio1 import PERFIS, recomendar

ESPERADO = {
    "credenciais_do_SOC": ("MySQL", "CP", "A07"),
    "telemetria_de_sensores": ("MongoDB", "AP", "A09"),
    "trilha_de_auditoria": ("MongoDB", "CP", "A08"),
    "carrinho_de_licencas": ("MySQL", "CP", "A06"),
    "cache_de_sessoes": ("MongoDB", "AP", "A07"),
}

v = Verificador("Exercício 1 — recomendar(perfil)")
for nome, (banco, cap, owasp) in ESPERADO.items():
    r = recomendar(PERFIS[nome])
    obtido = (r["banco"], r["cap"], r["risco_owasp"].split()[0])
    v(f"{nome}: {banco} | {cap} | {owasp}", obtido == (banco, cap, owasp), obtido)
    v(f"{nome}: justificativa nomeia o erro inaceitável", r["justificativa"].startswith("Inaceitável:"))
    v(f"{nome}: saída tem exatamente as 4 chaves pedidas",
      set(r) == {"banco", "cap", "justificativa", "risco_owasp"})

justificativas = [recomendar(p)["justificativa"] for p in PERFIS.values()]
v("cada cenário tem justificativa própria", len(set(justificativas)) == len(justificativas))

for descricao, perfil_ruim in [
    ("perfil sem uma chave -> TypeError", {k: v_ for k, v_ in PERFIS["cache_de_sessoes"].items() if k != "dado_sensivel"}),
    ("perfil com chave extra -> TypeError", {**PERFIS["cache_de_sessoes"], "extra": True}),
    ("valor não booleano -> TypeError", {**PERFIS["cache_de_sessoes"], "dado_sensivel": "sim"}),
]:
    try:
        recomendar(perfil_ruim)
        v(descricao, False, "não levantou exceção")
    except TypeError:
        v(descricao, True)

v.encerrar()
