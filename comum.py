"""Utilidades compartilhadas pelos exercícios do CP2.

Credenciais vêm SEMPRE de variáveis de ambiente — nenhuma senha no código:

    MYSQL_PASSWORD                         obrigatória
    MYSQL_HOST, MYSQL_PORT, MYSQL_USER,    opcionais (padrão: localhost, 3306, root,
    MYSQL_DATABASE, MONGO_URI, MONGO_DB    seguranca, mongodb://localhost:27017/, seguranca)
"""
import os
from contextlib import contextmanager
from functools import cache

import mysql.connector
from flask import Flask, jsonify
from pymongo import MongoClient
from pymongo.database import Database
from werkzeug.exceptions import HTTPException

HEADERS_SEGURANCA = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",                       # anti-clickjacking
    "Content-Security-Policy": "default-src 'self'",
}

MENSAGENS_HTTP = {
    404: "recurso não encontrado",
    405: "método não permitido",
    413: "corpo da requisição grande demais",
    500: "erro interno",
}


def _env_obrigatoria(nome: str) -> str:
    try:
        return os.environ[nome]
    except KeyError:
        raise RuntimeError(f"Defina a variável de ambiente {nome} antes de executar.") from None


@cache
def mongo_db() -> Database:
    """Banco MongoDB compartilhado (o MongoClient já é um pool thread-safe)."""
    cliente = MongoClient(
        os.environ.get("MONGO_URI", "mongodb://localhost:27017/"),
        serverSelectionTimeoutMS=3000,
        tz_aware=True,          # datas voltam com fuso (UTC), sem ambiguidade
    )
    return cliente[os.environ.get("MONGO_DB", "seguranca")]


@contextmanager
def mysql_conexao():
    """Abre uma conexão MySQL e garante o fechamento, mesmo em caso de erro."""
    conexao = mysql.connector.connect(
        host=os.environ.get("MYSQL_HOST", "localhost"),
        port=int(os.environ.get("MYSQL_PORT", "3306")),
        user=os.environ.get("MYSQL_USER", "root"),
        password=_env_obrigatoria("MYSQL_PASSWORD"),
        database=os.environ.get("MYSQL_DATABASE", "seguranca"),
        time_zone="+00:00",     # TIMESTAMPs lidos e gravados sempre em UTC
        connection_timeout=5,
    )
    try:
        yield conexao
    finally:
        conexao.close()


def configurar_api(app: Flask) -> Flask:
    """Headers de segurança em toda resposta e erros em JSON sem detalhes internos (A02/A10)."""

    @app.after_request
    def _headers_seguranca(resposta):
        resposta.headers.update(HEADERS_SEGURANCA)
        return resposta

    @app.errorhandler(HTTPException)
    def _erro_http(erro):
        # Exceções não tratadas chegam aqui como 500: o traceback vai para o log do
        # servidor, nunca para o cliente.
        return jsonify(erro=MENSAGENS_HTTP.get(erro.code, erro.name.lower())), erro.code

    return app
