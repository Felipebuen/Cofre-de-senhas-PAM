"""
Servidor Web - Cofre de Senhas PAM
API Flask que serve a interface e expõe endpoints REST.
"""

import os
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory, session

from backend.crypto import avaliar_forca_senha, gerar_senha, kdf_info
from backend.vault import (
    Cofre,
    CofreNaoInicializadoError,
    CredencialNaoEncontradaError,
    SenhaMestraIncorretaError,
)

# ------------------------------------------------------------------ #
#  Configuração                                                       #
# ------------------------------------------------------------------ #

BASE_DIR  = Path(__file__).parent
DATA_DIR  = BASE_DIR / "data"
VAULT_PATH = DATA_DIR / "vault.json"

app = Flask(
    __name__,
    static_folder=str(BASE_DIR / "frontend" / "static"),
    template_folder=str(BASE_DIR / "frontend" / "templates"),
)
app.secret_key = os.urandom(32)  # gerado a cada inicialização (sessões de memória)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"

cofre = Cofre(str(VAULT_PATH))


# ------------------------------------------------------------------ #
#  Decorators                                                         #
# ------------------------------------------------------------------ #

def requer_autenticado(f):
    @wraps(f)
    def decorado(*args, **kwargs):
        if not session.get("autenticado") or not cofre.aberto:
            return jsonify({"erro": "Não autenticado"}), 401
        return f(*args, **kwargs)
    return decorado


# ------------------------------------------------------------------ #
#  Rotas da interface                                                 #
# ------------------------------------------------------------------ #

@app.route("/")
def index():
    return send_from_directory(app.template_folder, "index.html")


# ------------------------------------------------------------------ #
#  API - Autenticação                                                 #
# ------------------------------------------------------------------ #

@app.route("/api/status", methods=["GET"])
def status():
    return jsonify({
        "cofre_existe": cofre.existe(),
        "autenticado": bool(session.get("autenticado") and cofre.aberto),
        "kdf": kdf_info(),
    })


@app.route("/api/inicializar", methods=["POST"])
def inicializar():
    dados = request.get_json()
    senha = dados.get("senha_mestra", "")
    if len(senha) < 8:
        return jsonify({"erro": "Senha mestra deve ter pelo menos 8 caracteres"}), 400
    try:
        cofre.inicializar(senha)
        session["autenticado"] = True
        return jsonify({"ok": True, "mensagem": "Cofre criado com sucesso"})
    except FileExistsError as e:
        return jsonify({"erro": str(e)}), 409


@app.route("/api/login", methods=["POST"])
def login():
    dados = request.get_json()
    senha = dados.get("senha_mestra", "")
    try:
        cofre.abrir(senha)
        session["autenticado"] = True
        return jsonify({"ok": True})
    except CofreNaoInicializadoError as e:
        return jsonify({"erro": str(e)}), 404
    except SenhaMestraIncorretaError:
        return jsonify({"erro": "Senha mestra incorreta"}), 401


@app.route("/api/logout", methods=["POST"])
def logout():
    cofre.fechar()
    session.clear()
    return jsonify({"ok": True})


# ------------------------------------------------------------------ #
#  API - Credenciais                                                  #
# ------------------------------------------------------------------ #

@app.route("/api/credenciais", methods=["GET"])
@requer_autenticado
def listar():
    termo = request.args.get("q", "").strip()
    if termo:
        resultado = cofre.buscar_credenciais(termo)
    else:
        resultado = cofre.listar_credenciais()
    return jsonify(resultado)


@app.route("/api/credenciais", methods=["POST"])
@requer_autenticado
def adicionar():
    dados = request.get_json()
    titulo = (dados.get("titulo") or "").strip()
    usuario = (dados.get("usuario") or "").strip()
    senha = dados.get("senha") or ""

    if not titulo:
        return jsonify({"erro": "Título é obrigatório"}), 400
    if not senha:
        return jsonify({"erro": "Senha é obrigatória"}), 400

    cred_id = cofre.adicionar_credencial(
        titulo=titulo,
        usuario=usuario,
        senha=senha,
        url=dados.get("url", ""),
        notas=dados.get("notas", ""),
        categoria=dados.get("categoria", "Geral"),
    )
    return jsonify({"ok": True, "id": cred_id}), 201


@app.route("/api/credenciais/<cred_id>", methods=["GET"])
@requer_autenticado
def obter(cred_id):
    try:
        cred = cofre.obter_credencial(cred_id)
        return jsonify(cred)
    except CredencialNaoEncontradaError:
        return jsonify({"erro": "Credencial não encontrada"}), 404


@app.route("/api/credenciais/<cred_id>", methods=["PUT"])
@requer_autenticado
def atualizar(cred_id):
    dados = request.get_json()
    try:
        cofre.atualizar_credencial(
            cred_id=cred_id,
            titulo=dados.get("titulo", ""),
            usuario=dados.get("usuario", ""),
            senha=dados.get("senha", ""),
            url=dados.get("url", ""),
            notas=dados.get("notas", ""),
            categoria=dados.get("categoria", "Geral"),
        )
        return jsonify({"ok": True})
    except CredencialNaoEncontradaError:
        return jsonify({"erro": "Credencial não encontrada"}), 404


@app.route("/api/credenciais/<cred_id>", methods=["DELETE"])
@requer_autenticado
def remover(cred_id):
    try:
        cofre.remover_credencial(cred_id)
        return jsonify({"ok": True})
    except CredencialNaoEncontradaError:
        return jsonify({"erro": "Credencial não encontrada"}), 404


# ------------------------------------------------------------------ #
#  API - Utilitários                                                  #
# ------------------------------------------------------------------ #

@app.route("/api/gerar-senha", methods=["GET"])
def api_gerar_senha():
    comprimento = int(request.args.get("comprimento", 16))
    maiusculas   = request.args.get("maiusculas",  "true") == "true"
    numeros      = request.args.get("numeros",     "true") == "true"
    simbolos     = request.args.get("simbolos",    "true") == "true"

    comprimento = max(4, min(128, comprimento))
    senha = gerar_senha(comprimento, maiusculas, numeros, simbolos)
    forca = avaliar_forca_senha(senha)
    return jsonify({"senha": senha, "forca": forca})


@app.route("/api/avaliar-senha", methods=["POST"])
def api_avaliar_senha():
    dados = request.get_json()
    senha = dados.get("senha", "")
    return jsonify(avaliar_forca_senha(senha))


@app.route("/api/estatisticas", methods=["GET"])
@requer_autenticado
def estatisticas():
    return jsonify(cofre.estatisticas())


@app.route("/api/alterar-senha-mestra", methods=["POST"])
@requer_autenticado
def alterar_senha_mestra():
    dados = request.get_json()
    senha_atual = dados.get("senha_atual", "")
    senha_nova = dados.get("senha_nova", "")
    if len(senha_nova) < 8:
        return jsonify({"erro": "Nova senha deve ter pelo menos 8 caracteres"}), 400
    try:
        cofre.alterar_senha_mestra(senha_atual, senha_nova)
        return jsonify({"ok": True, "mensagem": "Senha mestra alterada com sucesso"})
    except SenhaMestraIncorretaError:
        return jsonify({"erro": "Senha atual incorreta"}), 401


# ------------------------------------------------------------------ #
#  Entry point                                                        #
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    print("=" * 60)
    print("  Cofre de Senhas PAM — servidor iniciando")
    print(f"  KDF em uso: {kdf_info()}")
    print(f"  Cofre: {VAULT_PATH}")
    print("  Acesse: http://localhost:5000")
    print("=" * 60)
    app.run(debug=False, host="127.0.0.1", port=5000)
