"""
Módulo de Criptografia - Cofre de Senhas PAM
Implementa AES-256-GCM para cifragem e Argon2id para derivação de chave.
"""

import os
import base64
import hashlib
import secrets
import string
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Tentativa de usar Argon2; fallback para PBKDF2 se não disponível
try:
    from argon2.low_level import hash_secret_raw, Type
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False


# Constantes de segurança
ARGON2_TIME_COST    = 3        # iterações
ARGON2_MEMORY_COST  = 65536   # 64 MB
ARGON2_PARALLELISM  = 2
KEY_LENGTH          = 32       # 256 bits
SALT_LENGTH         = 32       # 256 bits
NONCE_LENGTH        = 12       # 96 bits (padrão GCM)
PBKDF2_ITERATIONS   = 600_000  # OWASP 2023 recommendation


def gerar_salt() -> bytes:
    """Gera salt criptograficamente seguro."""
    return secrets.token_bytes(SALT_LENGTH)


def derivar_chave(senha: str, salt: bytes) -> bytes:
    """
    Deriva uma chave de 256 bits a partir da senha mestra.
    Usa Argon2id se disponível, caso contrário PBKDF2-SHA256.
    """
    senha_bytes = senha.encode("utf-8")

    if ARGON2_AVAILABLE:
        chave = hash_secret_raw(
            secret=senha_bytes,
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=KEY_LENGTH,
            type=Type.ID,
        )
    else:
        # Fallback seguro: PBKDF2-HMAC-SHA256
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        chave = kdf.derive(senha_bytes)

    return chave


def cifrar(dados: str, chave: bytes) -> dict:
    """
    Cifra uma string com AES-256-GCM.
    Retorna dicionário com nonce e ciphertext em base64.
    """
    aesgcm = AESGCM(chave)
    nonce = secrets.token_bytes(NONCE_LENGTH)
    dados_bytes = dados.encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, dados_bytes, None)

    return {
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }


def decifrar(nonce_b64: str, ciphertext_b64: str, chave: bytes) -> str:
    """
    Decifra dados cifrados com AES-256-GCM.
    Lança InvalidTag se a chave for incorreta ou dados corrompidos.
    """
    aesgcm = AESGCM(chave)
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    dados_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    return dados_bytes.decode("utf-8")


def hash_senha_mestra(senha: str, salt: bytes) -> str:
    """
    Gera hash de verificação da senha mestra (para login sem expor a chave).
    Usa SHA-256 sobre a chave derivada com um domínio separado.
    """
    chave = derivar_chave(senha, salt)
    verificador = hashlib.sha256(b"verify:" + chave).hexdigest()
    return verificador


def gerar_senha(
    comprimento: int = 16,
    maiusculas: bool = True,
    numeros: bool = True,
    simbolos: bool = True,
) -> str:
    """
    Gera senha aleatória criptograficamente segura.
    """
    if comprimento < 4:
        comprimento = 4

    alfabeto = string.ascii_lowercase
    obrigatorios = []

    if maiusculas:
        alfabeto += string.ascii_uppercase
        obrigatorios.append(secrets.choice(string.ascii_uppercase))
    if numeros:
        alfabeto += string.digits
        obrigatorios.append(secrets.choice(string.digits))
    if simbolos:
        simbolos_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        alfabeto += simbolos_chars
        obrigatorios.append(secrets.choice(simbolos_chars))

    restante = comprimento - len(obrigatorios)
    senha_lista = obrigatorios + [secrets.choice(alfabeto) for _ in range(restante)]

    # Embaralha para não ter padrão previsível
    secrets.SystemRandom().shuffle(senha_lista)
    return "".join(senha_lista)


def avaliar_forca_senha(senha: str) -> dict:
    """
    Avalia a força de uma senha e retorna pontuação e feedback.
    """
    pontos = 0
    feedback = []

    if len(senha) >= 12:
        pontos += 2
    elif len(senha) >= 8:
        pontos += 1
    else:
        feedback.append("Senha muito curta (mínimo 8 caracteres)")

    if any(c.isupper() for c in senha):
        pontos += 1
    else:
        feedback.append("Adicione letras maiúsculas")

    if any(c.islower() for c in senha):
        pontos += 1
    else:
        feedback.append("Adicione letras minúsculas")

    if any(c.isdigit() for c in senha):
        pontos += 1
    else:
        feedback.append("Adicione números")

    if any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in senha):
        pontos += 2
    else:
        feedback.append("Adicione símbolos especiais")

    if len(senha) >= 16:
        pontos += 1

    if pontos <= 2:
        nivel = "fraca"
        cor = "#ef4444"
    elif pontos <= 4:
        nivel = "média"
        cor = "#f59e0b"
    elif pontos <= 6:
        nivel = "forte"
        cor = "#10b981"
    else:
        nivel = "muito forte"
        cor = "#06b6d4"

    return {
        "pontos": pontos,
        "maximo": 8,
        "nivel": nivel,
        "cor": cor,
        "feedback": feedback,
    }


def kdf_info() -> str:
    """Retorna qual algoritmo KDF está sendo usado."""
    return "Argon2id" if ARGON2_AVAILABLE else "PBKDF2-HMAC-SHA256"
