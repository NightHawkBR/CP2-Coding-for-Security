# CP2 cumulativo — Coding for Security (exercícios 1 a 9)

## Preparação

```powershell
pip install -r requirements.txt

# Bancos (ver "Ambiente de Laboratório" da apostila): MongoDB em 27017 e MySQL em 3306,
# com um banco chamado `seguranca` no MySQL:
#   CREATE DATABASE IF NOT EXISTS seguranca;

# Credencial SEMPRE por variável de ambiente (nenhuma senha no código):
$env:MYSQL_PASSWORD = "<senha do root do seu MySQL>"
# Opcionais: MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_DATABASE, MONGO_URI, MONGO_DB
```

## Executando

| Arquivo | Tipo | O que faz |
|---|---|---|
| `exercicio1.py` | script | `recomendar(perfil)` guiado por tabelas de regras |
| `exercicio2.py` | script | migra `ativos`/`alertas` do MySQL para documentos aninhados no Mongo |
| `exercicio3.py` | script | índice TTL + falhas por hora (agregação) |
| `exercicio4.py` | script | `alterar_nivel` transacional com trilha de auditoria |
| `exercicio5.py` | API | `GET /api/eventos` com `ORDER BY` por whitelist |
| `exercicio6.py` | API | incidentes com `X-API-Key`, 401/403/404 |
| `exercicio7.py` | API | `/dashboard` (Jinja2) × `/dashboard-inseguro` |
| `exercicio8.py` | API | `POST /api/triagem` e `GET /api/modelo/metricas` |
| `exercicio9.py` | API | log de acessos + IsolationForest -> 429 |

As APIs sobem em `http://127.0.0.1:5000` com `debug=False`. `comum.py` concentra as conexões
(lidas do ambiente), os headers de segurança e as respostas de erro em JSON sem detalhes internos.

> ⚠️ Os scripts recriam as próprias tabelas e coleções de laboratório no banco `seguranca`
> (`ativos`, `alertas`, `usuarios`, `eventos`, `analistas`, `incidentes` e as coleções equivalentes).

## Testes

Cada teste sobe o app num servidor HTTP real e o exercita com `requests`:

```powershell
foreach ($n in 1..9) { python "testes\teste_ex$n.py" }
```

`testes/teste_ex9.py` é o roteiro de teste pedido no Exercício 9.

## Decisões de interpretação

- **Ex. 6:** só nível ≥ 5 apaga incidentes. Para quem não tem esse nível, "não existe" e "não é seu"
  recebem o mesmo 403 com o mesmo corpo, então o código de status não revela quais ids existem.
  As API keys ficam gravadas como hash SHA-256 (coluna `api_key_hash`).
- **Ex. 7:** o CSP vale também para `/dashboard-inseguro`. O HTML dessa rota traz o payload cru
  (o teste comprova isso), mas o CSP impede a execução: é a segunda camada de defesa.
- **Ex. 9:** o IP vem de `request.remote_addr`. Só o teste usa `ProxyFix` para simular IPs via
  `X-Forwarded-For`; o app não confia nesse header, que o atacante poderia forjar. O bloqueio exige
  pelo menos 5 IPs na janela e só vale para quem desvia *para cima* da mediana: um IP quieto também é
  "raro" para o IsolationForest, mas não é ameaça.
