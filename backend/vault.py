"""
Módulo de Armazenamento - Cofre de Senhas PAM
Gerencia o banco de dados criptografado de credenciais.
"""

import json
import os
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


class Cofre:
    """
    Gerencia o cofre de senhas criptografado.
    O arquivo vault.json contém:
      - Metadados (versão, salt, hash de verificação)
      - Lista de credenciais cifradas individualmente com AES-256-GCM
    """

    def __init__(self, caminho_vault: str):
        self.caminho_vault = Path(caminho_vault)
        self._chave: Optional[bytes] = None
        self._dados: Optional[dict] = None

    # ------------------------------------------------------------------ #
    #  Inicialização e abertura                                            #
    # ------------------------------------------------------------------ #

    def inicializar(self, senha_mestra: str) -> None:
        """Cria um novo cofre com a senha mestra fornecida."""
        if self.caminho_vault.exists():
            raise FileExistsError("Um cofre já existe neste caminho.")

        salt = gerar_salt()
        verificador = hash_senha_mestra(senha_mestra, salt)

        estrutura = {
            "versao": VAULT_VERSION,
            "criado_em": _agora(),
            "salt": _b64e(salt),
            "verificador": verificador,
            "credenciais": [],
        }

        self.caminho_vault.parent.mkdir(parents=True, exist_ok=True)
        self._salvar_raw(estrutura)
        self._chave = derivar_chave(senha_mestra, salt)
        self._dados = estrutura

    def abrir(self, senha_mestra: str) -> None:
        """Abre o cofre existente verificando a senha mestra."""
        if not self.caminho_vault.exists():
            raise CofreNaoInicializadoError("Nenhum cofre encontrado.")

        raw = self._carregar_raw()
        salt = _b64d(raw["salt"])
        verificador_esperado = raw["verificador"]
        verificador_calculado = hash_senha_mestra(senha_mestra, salt)

        if verificador_calculado != verificador_esperado:
            raise SenhaMestraIncorretaError("Senha mestra incorreta.")

        self._chave = derivar_chave(senha_mestra, salt)
        self._dados = raw

    def fechar(self) -> None:
        """Limpa a chave da memória."""
        self._chave = None
        self._dados = None

    @property
    def aberto(self) -> bool:
        return self._chave is not None

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
    ) -> str:
        """Adiciona uma nova credencial cifrada. Retorna o ID gerado."""
        self._requer_aberto()

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

        cifrado = cifrar(payload, self._chave)
        entrada = {
            "id": cred_id,
            "titulo_visivel": titulo,     # título em texto plano para listagem
            "categoria": categoria,
            "criado_em": _agora(),
            "atualizado_em": _agora(),
            "nonce": cifrado["nonce"],
            "ciphertext": cifrado["ciphertext"],
        }

        self._dados["credenciais"].append(entrada)
        self._salvar_raw(self._dados)
        return cred_id

    def listar_credenciais(self) -> list[dict]:
        """Retorna metadados visíveis (sem dados sensíveis) de todas as credenciais."""
        self._requer_aberto()
        return [
            {
                "id": c["id"],
                "titulo": c["titulo_visivel"],
                "categoria": c["categoria"],
                "criado_em": c["criado_em"],
                "atualizado_em": c["atualizado_em"],
            }
            for c in self._dados["credenciais"]
        ]

    def obter_credencial(self, cred_id: str) -> dict:
        """Decifra e retorna todos os dados de uma credencial."""
        self._requer_aberto()
        entrada = self._buscar_entrada(cred_id)
        payload_str = decifrar(entrada["nonce"], entrada["ciphertext"], self._chave)
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
    ) -> None:
        """Atualiza uma credencial existente."""
        self._requer_aberto()
        entrada = self._buscar_entrada(cred_id)

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

        cifrado = cifrar(payload, self._chave)
        entrada["titulo_visivel"] = titulo
        entrada["categoria"] = categoria
        entrada["atualizado_em"] = _agora()
        entrada["nonce"] = cifrado["nonce"]
        entrada["ciphertext"] = cifrado["ciphertext"]

        self._salvar_raw(self._dados)

    def remover_credencial(self, cred_id: str) -> None:
        """Remove permanentemente uma credencial."""
        self._requer_aberto()
        self._buscar_entrada(cred_id)  # lança se não encontrar
        self._dados["credenciais"] = [
            c for c in self._dados["credenciais"] if c["id"] != cred_id
        ]
        self._salvar_raw(self._dados)

    def buscar_credenciais(self, termo: str) -> list[dict]:
        """Busca credenciais pelo título (case-insensitive)."""
        self._requer_aberto()
        termo_lower = termo.lower()
        return [
            {
                "id": c["id"],
                "titulo": c["titulo_visivel"],
                "categoria": c["categoria"],
                "criado_em": c["criado_em"],
                "atualizado_em": c["atualizado_em"],
            }
            for c in self._dados["credenciais"]
            if termo_lower in c["titulo_visivel"].lower()
            or termo_lower in c["categoria"].lower()
        ]

    def alterar_senha_mestra(self, senha_atual: str, senha_nova: str) -> None:
        """Re-cifra todas as credenciais com nova senha mestra."""
        self._requer_aberto()

        # Verifica senha atual
        salt_atual = _b64d(self._dados["salt"])
        if hash_senha_mestra(senha_atual, salt_atual) != self._dados["verificador"]:
            raise SenhaMestraIncorretaError("Senha atual incorreta.")

        # Decifra tudo com chave atual
        payloads = []
        for entrada in self._dados["credenciais"]:
            txt = decifrar(entrada["nonce"], entrada["ciphertext"], self._chave)
            payloads.append((entrada, txt))

        # Gera novo salt e chave
        novo_salt = gerar_salt()
        nova_chave = derivar_chave(senha_nova, novo_salt)
        novo_verificador = hash_senha_mestra(senha_nova, novo_salt)

        # Re-cifra tudo
        for entrada, txt in payloads:
            cifrado = cifrar(txt, nova_chave)
            entrada["nonce"] = cifrado["nonce"]
            entrada["ciphertext"] = cifrado["ciphertext"]
            entrada["atualizado_em"] = _agora()

        self._dados["salt"] = _b64e(novo_salt)
        self._dados["verificador"] = novo_verificador
        self._chave = nova_chave
        self._salvar_raw(self._dados)

    def estatisticas(self) -> dict:
        """Retorna estatísticas do cofre."""
        self._requer_aberto()
        total = len(self._dados["credenciais"])
        categorias: dict[str, int] = {}
        for c in self._dados["credenciais"]:
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

    def _requer_aberto(self) -> None:
        if not self.aberto:
            raise CofreNaoInicializadoError("O cofre não está aberto.")

    def _buscar_entrada(self, cred_id: str) -> dict:
        for c in self._dados["credenciais"]:
            if c["id"] == cred_id:
                return c
        raise CredencialNaoEncontradaError(f"Credencial '{cred_id}' não encontrada.")

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
