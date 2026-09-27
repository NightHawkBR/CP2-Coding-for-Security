"""Exercício 1 — Assistente de decisão de armazenamento (Aulas 1 e 8).

A decisão vem de tabelas de regras ordenadas: cada regra diz QUANDO se aplica,
QUAL é a decisão e POR QUÊ. A primeira regra que casa com o perfil vence, então a
própria tabela documenta a prioridade dos critérios — nada de `if` espalhado.
"""
from dataclasses import astuple, dataclass
from typing import Callable


@dataclass(frozen=True)
class Perfil:
    schema_fixo: bool
    precisa_acid: bool
    escala_horizontal: bool
    tolera_atraso_de_consistencia: bool
    dado_sensivel: bool

    def __post_init__(self):
        if not all(isinstance(valor, bool) for valor in astuple(self)):
            raise TypeError("todas as características do perfil devem ser booleanas")


@dataclass(frozen=True)
class Regra:
    quando: Callable[[Perfil], bool]
    decisao: str
    motivo: str


# Banco: transação ACID manda; sem ela, a necessidade de escalar decide.
REGRAS_BANCO = (
    Regra(lambda p: p.precisa_acid, "MySQL",
          "Exige transações ACID entre linhas relacionadas, terreno nativo do modelo relacional."),
    Regra(lambda p: p.escala_horizontal, "MongoDB",
          "O volume precisa crescer em vários nós, e o MongoDB distribui documentos por sharding."),
    Regra(lambda p: p.schema_fixo, "MySQL",
          "Schema estável ganha integridade com tipos e chaves estrangeiras."),
    Regra(lambda p: True, "MongoDB",
          "Schema variável cabe em documentos sem migrações a cada nova fonte."),
)

# CAP: a justificativa nomeia o erro que seria INACEITÁVEL no cenário.
REGRAS_CAP = (
    Regra(lambda p: not p.tolera_atraso_de_consistencia and p.precisa_acid and p.dado_sensivel, "CP",
          "Inaceitável: uma réplica atrasada aceitar uma senha ou permissão já revogada — "
          "autenticar errado é pior que ficar fora do ar."),
    Regra(lambda p: not p.tolera_atraso_de_consistencia and p.precisa_acid, "CP",
          "Inaceitável: dois nós confirmarem operações conflitantes (a mesma licença vendida "
          "duas vezes) — melhor recusar a venda durante a partição."),
    Regra(lambda p: not p.tolera_atraso_de_consistencia, "CP",
          "Inaceitável: réplicas contarem versões diferentes de quem fez o quê — "
          "auditoria divergente não vale como prova."),
    Regra(lambda p: p.dado_sensivel, "AP",
          "Inaceitável: derrubar o login de todos porque um nó ficou isolado — a janela de "
          "sessão desatualizada é curta e limitada pela expiração do token."),
    Regra(lambda p: True, "AP",
          "Inaceitável: parar de aceitar eventos no meio de um ataque — "
          "perder 1s de log custa menos que ficar cego."),
)

# OWASP 2025: o risco que a escolha ERRADA de banco/CAP criaria.
REGRAS_OWASP = (
    Regra(lambda p: p.precisa_acid and p.dado_sensivel, "A07 Authentication Failures",
          "consistência eventual deixa credencial revogada ainda válida em alguma réplica"),
    Regra(lambda p: p.precisa_acid, "A06 Insecure Design",
          "sem transação, requisições concorrentes viram falha de lógica de negócio (race condition)"),
    Regra(lambda p: p.dado_sensivel and not p.tolera_atraso_de_consistencia,
          "A08 Software or Data Integrity Failures",
          "réplicas eventuais permitem registros divergentes: a trilha perde integridade"),
    Regra(lambda p: p.dado_sensivel, "A07 Authentication Failures",
          "réplica atrasada pode aceitar token já encerrado no logout (mitigar com TTL curto)"),
    Regra(lambda p: True, "A09 Security Logging & Alerting Failures",
          "banco que recusa escrita sob partição descarta justamente os eventos do ataque"),
)


def _primeira_que_casa(regras: tuple[Regra, ...], perfil: Perfil) -> Regra:
    return next(regra for regra in regras if regra.quando(perfil))


def recomendar(perfil: dict) -> dict:
    """Recomenda banco, lado do CAP e risco OWASP para um perfil de dados."""
    p = Perfil(**perfil)   # chave faltando ou sobrando -> TypeError
    banco, cap, risco = (_primeira_que_casa(regras, p)
                         for regras in (REGRAS_BANCO, REGRAS_CAP, REGRAS_OWASP))
    return {
        "banco": banco.decisao,
        "cap": cap.decisao,
        "justificativa": f"{cap.motivo} {banco.motivo}",
        "risco_owasp": f"{risco.decisao} — {risco.motivo}",
    }


PERFIS = {
    "credenciais_do_SOC":     {"schema_fixo": True,  "precisa_acid": True,  "escala_horizontal": False, "tolera_atraso_de_consistencia": False, "dado_sensivel": True},
    "telemetria_de_sensores": {"schema_fixo": False, "precisa_acid": False, "escala_horizontal": True,  "tolera_atraso_de_consistencia": True,  "dado_sensivel": False},
    "trilha_de_auditoria":    {"schema_fixo": False, "precisa_acid": False, "escala_horizontal": True,  "tolera_atraso_de_consistencia": False, "dado_sensivel": True},
    "carrinho_de_licencas":   {"schema_fixo": True,  "precisa_acid": True,  "escala_horizontal": False, "tolera_atraso_de_consistencia": False, "dado_sensivel": False},
    "cache_de_sessoes":       {"schema_fixo": True,  "precisa_acid": False, "escala_horizontal": True,  "tolera_atraso_de_consistencia": True,  "dado_sensivel": True},
}


if __name__ == "__main__":
    for nome, perfil in PERFIS.items():
        r = recomendar(perfil)
        codigo_owasp = r["risco_owasp"].split()[0]
        print(f"{nome:<23} -> {r['banco']:<7} | {r['cap']} | {codigo_owasp}")
        print(f"    justificativa: {r['justificativa']}")
        print(f"    risco:         {r['risco_owasp']}\n")
