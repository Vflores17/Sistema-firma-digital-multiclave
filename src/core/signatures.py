# src/core/signatures.py

"""
signatures.py

Módulo para manejo de firmas digitales usando Ed25519.

Permite:
- generar pares de claves
- firmar datos
- verificar firmas
- exportar claves en formato PEM
"""

import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey
)
from cryptography.hazmat.primitives import serialization


def generate_keypair():
    """
    Genera un par de claves Ed25519.
    """

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    return private_key, public_key


def export_private_key_pem(private_key):
    """
    Exporta clave privada en formato PEM.
    """

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    return pem.decode()


def export_public_key_pem(public_key):
    """
    Exporta clave pública en formato PEM.
    """

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem.decode()


def load_private_key_pem(pem_text: str):
    """
    Carga clave privada desde PEM.
    """

    return serialization.load_pem_private_key(
        pem_text.encode(),
        password=None
    )


def load_public_key_pem(pem_text: str):
    """
    Carga clave pública desde PEM.
    """

    return serialization.load_pem_public_key(
        pem_text.encode()
    )


def sign_data(private_key, data: bytes) -> str:
    """
    Firma datos.

    Devuelve la firma en Base64.
    """

    signature = private_key.sign(data)

    return base64.b64encode(signature).decode()


def verify_signature(public_key, data: bytes, signature_b64: str) -> bool:
    """
    Verifica una firma.
    """

    try:
        signature = base64.b64decode(signature_b64)

        public_key.verify(signature, data)

        return True

    except Exception:
        return False