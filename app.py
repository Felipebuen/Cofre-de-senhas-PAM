"""
Servidor Web - Cofre de Senhas PAM
API Flask que serve a interface e expõe endpoints REST.
"""

import os
import secrets
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory, session

from backend.crypto import avaliar_forca_senha, gerar_senha, kdf_info
from backend.vault import (
    Cofre,
    CofreNaoInicializadoError,
    CredencialNaoEncontradaError,
    PerfilExistenteError,
    PerfilNaoEncontradoError,
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
        perfil = session.get("perfil", "")
        sessao_id = session.get("sessao_id", "")
        if not session.get("autenticado") or not cofre.esta_aberto(perfil, sessao_id):
            return jsonify({"erro": "Não autenticado"}), 401
        with cofre.trava:
            return f(*args, **kwargs)
    return decorado


def contexto_sessao():
    return session.get("perfil", "Principal"), session.get("sessao_id", "")


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
    perfil, sessao_id = contexto_sessao()
    return jsonify({
        "cofre_existe": cofre.existe(),
        "perfis": cofre.listar_perfis(),
        "perfil_principal": cofre.perfil_principal(),
        "perfil_atual": perfil if session.get("autenticado") else None,
        "autenticado": bool(session.get("autenticado") and cofre.esta_aberto(perfil, sessao_id)),
        "kdf": kdf_info(),
    })


@app.route("/api/inicializar", methods=["POST"])
def inicializar():
    dados = request.get_json(silent=True) or {}
    senha = dados.get("senha_mestra", "")
    perfil = dados.get("perfil", "Principal")
    if len(senha) < 8:
        return jsonify({"erro": "Senha mestra deve ter pelo menos 8 caracteres"}), 400
    try:
        sessao_id = secrets.token_urlsafe(24)
        cofre.inicializar(senha, perfil, sessao_id)
        session["autenticado"] = True
        session["perfil"] = perfil.strip()
        session["sessao_id"] = sessao_id
        return jsonify({"ok": True, "mensagem": "Cofre criado com sucesso"})
    except FileExistsError as e:
        return jsonify({"erro": str(e)}), 409
    except ValueError as e:
        return jsonify({"erro": str(e)}), 400


@app.route("/api/login", methods=["POST"])
def login():
    dados = request.get_json(silent=True) or {}
    senha = dados.get("senha_mestra", "")
    perfil = dados.get("perfil", "")
    if not isinstance(perfil, str) or not perfil.strip():
        return jsonify({"erro": "Nome do perfil é obrigatório"}), 400
    if not isinstance(senha, str):
        return jsonify({"erro": "Senha mestra inválida"}), 400
    sessao_id = secrets.token_urlsafe(24)
    try:
        cofre.abrir(senha, perfil, sessao_id)
        session["autenticado"] = True
        session["perfil"] = perfil.strip()
        session["sessao_id"] = sessao_id
        return jsonify({"ok": True})
    except CofreNaoInicializadoError as e:
        return jsonify({"erro": str(e)}), 404
    except PerfilNaoEncontradoError as e:
        return jsonify({"erro": str(e)}), 404
    except SenhaMestraIncorretaError:
        return jsonify({"erro": "Senha mestra incorreta"}), 401
    except ValueError as e:
        return jsonify({"erro": str(e)}), 400


@app.route("/api/perfis/registrar", methods=["POST"])
def registrar_perfil():
    dados = request.get_json(silent=True) or {}
    perfil_principal = dados.get("perfil_principal", "")
    senha_principal = dados.get("senha_principal", "")
    nome = dados.get("perfil", "")
    senha = dados.get("senha_mestra", "")
    if not all(isinstance(valor, str) for valor in (
        perfil_principal, senha_principal, nome, senha
    )):
        return jsonify({"erro": "Preencha os dados do perfil principal e do novo perfil"}), 400
    if len(senha) < 8:
        return jsonify({"erro": "Senha mestra deve ter pelo menos 8 caracteres"}), 400
    try:
        cofre.criar_perfil_com_senha_principal(
            nome, senha, perfil_principal, senha_principal
        )
        return jsonify({"ok": True, "perfis": cofre.listar_perfis()}), 201
    except CofreNaoInicializadoError as e:
        return jsonify({"erro": str(e)}), 404
    except PerfilNaoEncontradoError as e:
        return jsonify({"erro": str(e)}), 404
    except SenhaMestraIncorretaError:
        return jsonify({"erro": "Senha mestra do perfil principal incorreta"}), 401
    except PerfilExistenteError as e:
        return jsonify({"erro": str(e)}), 409
    except ValueError as e:
        return jsonify({"erro": str(e)}), 400


@app.route("/api/perfis", methods=["POST"])
@requer_autenticado
def criar_perfil():
    dados = request.get_json(silent=True) or {}
    nome = dados.get("perfil", "")
    senha = dados.get("senha_mestra", "")
    if len(senha) < 8:
        return jsonify({"erro": "Senha mestra deve ter pelo menos 8 caracteres"}), 400
    perfil_atual, sessao_id = contexto_sessao()
    try:
        cofre.criar_perfil(nome, senha, perfil_atual, sessao_id)
        return jsonify({"ok": True, "perfis": cofre.listar_perfis()}), 201
    except PerfilExistenteError as e:
        return jsonify({"erro": str(e)}), 409
    except ValueError as e:
        return jsonify({"erro": str(e)}), 400


@app.route("/api/logout", methods=["POST"])
def logout():
    cofre.fechar(session.get("sessao_id"))
    session.clear()
    return jsonify({"ok": True})


# ------------------------------------------------------------------ #
#  API - Credenciais                                                  #
# ------------------------------------------------------------------ #

@app.route("/api/credenciais", methods=["GET"])
@requer_autenticado
def listar():
    perfil, sessao_id = contexto_sessao()
    termo = request.args.get("q", "").strip()
    if termo:
        resultado = cofre.buscar_credenciais(termo, perfil, sessao_id)
    else:
        resultado = cofre.listar_credenciais(perfil, sessao_id)
    return jsonify(resultado)


@app.route("/api/credenciais", methods=["POST"])
@requer_autenticado
def adicionar():
    dados = request.get_json(silent=True) or {}
    titulo = (dados.get("titulo") or "").strip()
    usuario = (dados.get("usuario") or "").strip()
    senha = dados.get("senha") or ""

    if not titulo:
        return jsonify({"erro": "Título é obrigatório"}), 400
    if not senha:
        return jsonify({"erro": "Senha é obrigatória"}), 400

    perfil, sessao_id = contexto_sessao()
    cred_id = cofre.adicionar_credencial(
        titulo=titulo,
        usuario=usuario,
        senha=senha,
        url=dados.get("url", ""),
        notas=dados.get("notas", ""),
        categoria=dados.get("categoria", "Geral"),
        perfil=perfil,
        sessao_id=sessao_id,
    )
    return jsonify({"ok": True, "id": cred_id}), 201


@app.route("/api/credenciais/<cred_id>", methods=["GET"])
@requer_autenticado
def obter(cred_id):
    perfil, sessao_id = contexto_sessao()
    try:
        cred = cofre.obter_credencial(cred_id, perfil, sessao_id)
        return jsonify(cred)
    except CredencialNaoEncontradaError:
        return jsonify({"erro": "Credencial não encontrada"}), 404


@app.route("/api/credenciais/<cred_id>", methods=["PUT"])
@requer_autenticado
def atualizar(cred_id):
    dados = request.get_json(silent=True) or {}
    perfil, sessao_id = contexto_sessao()
    try:
        cofre.atualizar_credencial(
            cred_id=cred_id,
            titulo=dados.get("titulo", ""),
            usuario=dados.get("usuario", ""),
            senha=dados.get("senha", ""),
            url=dados.get("url", ""),
            notas=dados.get("notas", ""),
            categoria=dados.get("categoria", "Geral"),
            perfil=perfil,
            sessao_id=sessao_id,
        )
        return jsonify({"ok": True})
    except CredencialNaoEncontradaError:
        return jsonify({"erro": "Credencial não encontrada"}), 404


@app.route("/api/credenciais/<cred_id>", methods=["DELETE"])
@requer_autenticado
def remover(cred_id):
    perfil, sessao_id = contexto_sessao()
    try:
        cofre.remover_credencial(cred_id, perfil, sessao_id)
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
    perfil, sessao_id = contexto_sessao()
    return jsonify(cofre.estatisticas(perfil, sessao_id))


@app.route("/api/alterar-senha-mestra", methods=["POST"])
@requer_autenticado
def alterar_senha_mestra():
    dados = request.get_json(silent=True) or {}
    senha_atual = dados.get("senha_atual", "")
    senha_nova = dados.get("senha_nova", "")
    if len(senha_nova) < 8:
        return jsonify({"erro": "Nova senha deve ter pelo menos 8 caracteres"}), 400
    perfil, sessao_id = contexto_sessao()
    try:
        cofre.alterar_senha_mestra(senha_atual, senha_nova, perfil, sessao_id)
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
