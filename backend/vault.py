"""
Módulo de Armazenamento - Cofre de Senhas PAM
Gerencia o banco de dados criptografado de credenciais.
"""

import json
import os
import secrets
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from backend.crypto import (
    cifrar,
    decifrar,
    derivar_chave,
    gerar_salt,
    hash_senha_mestra,
)

VAULT_VERSION = "1.0"


class CofreNaoInicializadoError(Exception):
    pass


class SenhaMestraIncorretaError(Exception):
    pass


class CredencialNaoEncontradaError(Exception):
    pass


class PerfilNaoEncontradoError(Exception):
    pass


class PerfilExistenteError(Exception):
    pass


class Cofre:
    """
    Gerencia o cofre de senhas criptografado.
    O arquivo vault.json contém:
      - Metadados (versão, salt, hash de verificação)
      - Lista de credenciais cifradas individualmente com AES-256-GCM
    """

    def __init__(self, caminho_vault: str):
        self.caminho_vault = Path(caminho_vault)
        self._chaves: dict[tuple[str, str], bytes] = {}
        self._dados: Optional[dict] = None
        self.trava = threading.RLock()

    # ------------------------------------------------------------------ #
    #  Inicialização e abertura                                            #
    # ------------------------------------------------------------------ #

    def inicializar(
        self, senha_mestra: str, perfil: str = "Principal", sessao_id: str = "local"
    ) -> None:
        """Cria o cofre e seu primeiro perfil."""
        if self.caminho_vault.exists():
            raise FileExistsError("Um cofre já existe neste caminho.")
        nome, chave_perfil = self._validar_nome_perfil(perfil)
        salt = gerar_salt()
        registro = self._novo_perfil(nome, senha_mestra, salt)
        estrutura = {
            "versao": "2.0",
            "criado_em": _agora(),
            "perfis": {chave_perfil: registro},
        }
        self.caminho_vault.parent.mkdir(parents=True, exist_ok=True)
        self._salvar_raw(estrutura)
        self._dados = estrutura
        self._chaves[(sessao_id, chave_perfil)] = derivar_chave(senha_mestra, salt)

    def abrir(
        self, senha_mestra: str, perfil: str = "Principal", sessao_id: str = "local"
    ) -> None:
        """Abre um perfil após verificar sua senha mestra."""
        if not self.caminho_vault.exists():
            raise CofreNaoInicializadoError("Nenhum cofre encontrado.")
        raw = self._carregar_raw()
        if "perfis" not in raw:
            raw = self._migrar_legado(raw)
            self._salvar_raw(raw)
        nome, chave_perfil = self._validar_nome_perfil(perfil)
        registro = raw["perfis"].get(chave_perfil)
        if registro is None:
            raise PerfilNaoEncontradoError("Perfil não encontrado.")
        salt = _b64d(registro["salt"])
        verificador = hash_senha_mestra(senha_mestra, salt)
        if not secrets.compare_digest(verificador, registro["verificador"]):
            raise SenhaMestraIncorretaError("Senha mestra incorreta.")
        self._dados = raw
        self._chaves[(sessao_id, chave_perfil)] = derivar_chave(senha_mestra, salt)

    def criar_perfil(
        self, nome: str, senha_mestra: str, perfil_atual: str, sessao_id: str
    ) -> None:
        """Cria um perfil isolado, autorizado por um perfil já autenticado."""
        self._requer_aberto(perfil_atual, sessao_id)
        nome, chave_perfil = self._validar_nome_perfil(nome)
        if chave_perfil in self._dados["perfis"]:
            raise PerfilExistenteError("Já existe um perfil com esse nome.")
        salt = gerar_salt()
        self._dados["perfis"][chave_perfil] = self._novo_perfil(nome, senha_mestra, salt)
        self._salvar_raw(self._dados)

    def listar_perfis(self) -> list[str]:
        if not self.caminho_vault.exists():
            return []
        raw = self._carregar_raw()
        if "perfis" not in raw:
            return ["Principal"]
        return sorted(p["nome"] for p in raw["perfis"].values())

    def fechar(self, sessao_id: Optional[str] = None) -> None:
        """Limpa uma sessão ou todas as chaves em memória."""
        if sessao_id is None:
            self._chaves.clear()
            self._dados = None
        else:
            self._chaves = {k: v for k, v in self._chaves.items() if k[0] != sessao_id}

    @property
    def aberto(self) -> bool:
        return bool(self._chaves)

    def esta_aberto(self, perfil: str, sessao_id: str) -> bool:
        try:
            _, chave_perfil = self._validar_nome_perfil(perfil)
        except ValueError:
            return False
        return (sessao_id, chave_perfil) in self._chaves

    def existe(self) -> bool:
        return self.caminho_vault.exists()

    # ------------------------------------------------------------------ #
    #  CRUD de credenciais                                                 #
    # ------------------------------------------------------------------ #

    def adicionar_credencial(
        self,
        titulo: str,
        usuario: str,
        senha: str,
        url: str = "",
        notas: str = "",
        categoria: str = "Geral",
        perfil: str = "Principal",
        sessao_id: str = "local",
    ) -> str:
        """Adiciona uma nova credencial cifrada. Retorna o ID gerado."""
        dados_perfil, chave = self._contexto(perfil, sessao_id)

        cred_id = str(uuid.uuid4())
        payload = json.dumps(
            {
                "titulo": titulo,
                "usuario": usuario,
                "senha": senha,
                "url": url,
                "notas": notas,
                "categoria": categoria,
            },
            ensure_ascii=False,
        )

        cifrado = cifrar(payload, chave)
        entrada = {
            "id": cred_id,
            "titulo_visivel": titulo,     # título em texto plano para listagem
            "categoria": categoria,
            "criado_em": _agora(),
            "atualizado_em": _agora(),
            "nonce": cifrado["nonce"],
            "ciphertext": cifrado["ciphertext"],
        }

        dados_perfil["credenciais"].append(entrada)
        self._salvar_perfil(perfil, dados_perfil)
        return cred_id

    def listar_credenciais(self, perfil: str = "Principal", sessao_id: str = "local") -> list[dict]:
        """Retorna metadados visíveis (sem dados sensíveis) de todas as credenciais."""
        dados_perfil, _ = self._contexto(perfil, sessao_id)
        return [
            {
                "id": c["id"],
                "titulo": c["titulo_visivel"],
                "categoria": c["categoria"],
                "criado_em": c["criado_em"],
                "atualizado_em": c["atualizado_em"],
            }
            for c in dados_perfil["credenciais"]
        ]

    def obter_credencial(self, cred_id: str, perfil: str = "Principal", sessao_id: str = "local") -> dict:
        """Decifra e retorna todos os dados de uma credencial."""
        dados_perfil, chave = self._contexto(perfil, sessao_id)
        entrada = self._buscar_entrada(cred_id, dados_perfil)
        payload_str = decifrar(entrada["nonce"], entrada["ciphertext"], chave)
        payload = json.loads(payload_str)
        payload["id"] = cred_id
        payload["criado_em"] = entrada["criado_em"]
        payload["atualizado_em"] = entrada["atualizado_em"]
        return payload

    def atualizar_credencial(
        self,
        cred_id: str,
        titulo: str,
        usuario: str,
        senha: str,
        url: str = "",
        notas: str = "",
        categoria: str = "Geral",
        perfil: str = "Principal",
        sessao_id: str = "local",
    ) -> None:
        """Atualiza uma credencial existente."""
        dados_perfil, chave = self._contexto(perfil, sessao_id)
        entrada = self._buscar_entrada(cred_id, dados_perfil)

        payload = json.dumps(
            {
                "titulo": titulo,
                "usuario": usuario,
                "senha": senha,
                "url": url,
                "notas": notas,
                "categoria": categoria,
            },
            ensure_ascii=False,
        )

        cifrado = cifrar(payload, chave)
        entrada["titulo_visivel"] = titulo
        entrada["categoria"] = categoria
        entrada["atualizado_em"] = _agora()
        entrada["nonce"] = cifrado["nonce"]
        entrada["ciphertext"] = cifrado["ciphertext"]

        self._salvar_perfil(perfil, dados_perfil)

    def remover_credencial(self, cred_id: str, perfil: str = "Principal", sessao_id: str = "local") -> None:
        """Remove permanentemente uma credencial."""
        dados_perfil, _ = self._contexto(perfil, sessao_id)
        self._buscar_entrada(cred_id, dados_perfil)
        dados_perfil["credenciais"] = [
            c for c in dados_perfil["credenciais"] if c["id"] != cred_id
        ]
        self._salvar_perfil(perfil, dados_perfil)

    def buscar_credenciais(self, termo: str, perfil: str = "Principal", sessao_id: str = "local") -> list[dict]:
        """Busca credenciais pelo título (case-insensitive)."""
        dados_perfil, _ = self._contexto(perfil, sessao_id)
        termo_lower = termo.lower()
        return [
            {
                "id": c["id"],
                "titulo": c["titulo_visivel"],
                "categoria": c["categoria"],
                "criado_em": c["criado_em"],
                "atualizado_em": c["atualizado_em"],
            }
            for c in dados_perfil["credenciais"]
            if termo_lower in c["titulo_visivel"].lower()
            or termo_lower in c["categoria"].lower()
        ]

    def alterar_senha_mestra(
        self, senha_atual: str, senha_nova: str,
        perfil: str = "Principal", sessao_id: str = "local",
    ) -> None:
        """Troca a senha mestra e re-cifra somente o perfil atual."""
        dados_perfil, chave_atual = self._contexto(perfil, sessao_id)
        salt_atual = _b64d(dados_perfil["salt"])
        if not secrets.compare_digest(
            hash_senha_mestra(senha_atual, salt_atual), dados_perfil["verificador"]
        ):
            raise SenhaMestraIncorretaError("Senha atual incorreta.")
        payloads = []
        for entrada in dados_perfil["credenciais"]:
            txt = decifrar(entrada["nonce"], entrada["ciphertext"], chave_atual)
            payloads.append((entrada, txt))
        novo_salt = gerar_salt()
        nova_chave = derivar_chave(senha_nova, novo_salt)
        dados_perfil["verificador"] = hash_senha_mestra(senha_nova, novo_salt)
        dados_perfil["salt"] = _b64e(novo_salt)
        for entrada, txt in payloads:
            cifrado = cifrar(txt, nova_chave)
            entrada["nonce"] = cifrado["nonce"]
            entrada["ciphertext"] = cifrado["ciphertext"]
            entrada["atualizado_em"] = _agora()
        _, chave_perfil = self._validar_nome_perfil(perfil)
        self._salvar_perfil(perfil, dados_perfil)
        self._chaves = {
            identificador: chave
            for identificador, chave in self._chaves.items()
            if identificador[1] != chave_perfil or identificador[0] == sessao_id
        }
        self._chaves[(sessao_id, chave_perfil)] = nova_chave

    def estatisticas(self, perfil: str = "Principal", sessao_id: str = "local") -> dict:
        """Retorna estatísticas do cofre."""
        dados_perfil, _ = self._contexto(perfil, sessao_id)
        total = len(dados_perfil["credenciais"])
        categorias: dict[str, int] = {}
        for c in dados_perfil["credenciais"]:
            cat = c.get("categoria", "Geral")
            categorias[cat] = categorias.get(cat, 0) + 1
        return {
            "total_credenciais": total,
            "categorias": categorias,
            "versao": self._dados.get("versao", "?"),
            "criado_em": self._dados.get("criado_em", "?"),
        }

    # ------------------------------------------------------------------ #
    #  Helpers privados                                                    #
    # ------------------------------------------------------------------ #

    def _requer_aberto(self, perfil: str, sessao_id: str) -> bytes:
        _, chave_perfil = self._validar_nome_perfil(perfil)
        chave = self._chaves.get((sessao_id, chave_perfil))
        if chave is None:
            raise CofreNaoInicializadoError("O cofre não está aberto.")
        return chave

    def _contexto(self, perfil: str, sessao_id: str) -> tuple[dict, bytes]:
        _, chave_perfil = self._validar_nome_perfil(perfil)
        chave = self._requer_aberto(perfil, sessao_id)
        dados_perfil = self._dados["perfis"].get(chave_perfil)
        if dados_perfil is None:
            raise PerfilNaoEncontradoError("Perfil não encontrado.")
        return dados_perfil, chave

    def _buscar_entrada(self, cred_id: str, dados_perfil: dict) -> dict:
        for c in dados_perfil["credenciais"]:
            if c["id"] == cred_id:
                return c
        raise CredencialNaoEncontradaError(f"Credencial '{cred_id}' não encontrada.")

    def _salvar_perfil(self, perfil: str, dados_perfil: dict) -> None:
        _, chave_perfil = self._validar_nome_perfil(perfil)
        self._dados["perfis"][chave_perfil] = dados_perfil
        self._salvar_raw(self._dados)

    @staticmethod
    def _validar_nome_perfil(perfil: str) -> tuple[str, str]:
        nome = (perfil or "").strip()
        if not nome or len(nome) > 40:
            raise ValueError("O nome do perfil deve ter entre 1 e 40 caracteres.")
        return nome, nome.casefold()

    @staticmethod
    def _novo_perfil(nome: str, senha_mestra: str, salt: bytes) -> dict:
        return {
            "nome": nome,
            "salt": _b64e(salt),
            "verificador": hash_senha_mestra(senha_mestra, salt),
            "criado_em": _agora(),
            "credenciais": [],
        }

    @staticmethod
    def _migrar_legado(dados: dict) -> dict:
        return {
            "versao": "2.0",
            "criado_em": dados.get("criado_em", _agora()),
            "perfis": {
                "principal": {
                    "nome": "Principal",
                    "salt": dados["salt"],
                    "verificador": dados["verificador"],
                    "criado_em": dados.get("criado_em", _agora()),
                    "credenciais": dados.get("credenciais", []),
                }
            },
        }

    def _salvar_raw(self, dados: dict) -> None:
        tmp = str(self.caminho_vault) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(dados, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.caminho_vault)  # operação atômica

    def _carregar_raw(self) -> dict:
        with open(self.caminho_vault, "r", encoding="utf-8") as f:
            return json.load(f)


# ------------------------------------------------------------------ #
#  Utilitários                                                        #
# ------------------------------------------------------------------ #

import base64 as _base64


def _b64e(b: bytes) -> str:
    return _base64.b64encode(b).decode("utf-8")


def _b64d(s: str) -> bytes:
    return _base64.b64decode(s)


def _agora() -> str:
    return datetime.now(timezone.utc).isoformat()
