# src/core/hybrid_encryption.py

"""
hybrid_encryption.py

Cifrado híbrido RSA-OAEP + AES-256-GCM para el paquete certificado.

Flujo:
  CIFRAR:
    1. Generar clave AES-256 aleatoria
    2. Cifrar ZIP (PDF + bundle) con AES-256-GCM
    3. Cifrar la clave AES con la clave pública RSA del notario (OAEP/SHA-256)
    4. Empaquetar todo en un .pkg (ZIP interno con metadatos)

  DESCIFRAR:
    1. Cargar .pkg
    2. Descifrar la clave AES con la clave privada RSA del notario
    3. Descifrar el contenido con la clave AES
    4. Extraer PDF + bundle.json

Solo quien tenga la clave privada RSA del notario puede descifrar.
"""

import io
import json
import os
import zipfile
import pathlib
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ── Extensión del paquete certificado ──────────────────────────
PKG_EXT = ".certified"

# ── Generación de par de claves RSA ───────────────────────────

def generate_rsa_keypair(key_size: int = 2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    return private_key, private_key.public_key()


def export_private_key_pem(private_key) -> str:
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode()


def export_public_key_pem(public_key) -> str:
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def load_private_key_pem(pem: str):
    return serialization.load_pem_private_key(pem.encode(), password=None)


def load_public_key_pem(pem: str):
    return serialization.load_pem_public_key(pem.encode())


# ── Cifrado AES-256-GCM ────────────────────────────────────────

def _aes_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    ct    = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce, ct


def _aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, None)


# ── Cifrado RSA-OAEP ───────────────────────────────────────────

def _rsa_encrypt_key(public_key, aes_key: bytes) -> bytes:
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def _rsa_decrypt_key(private_key, encrypted_key: bytes) -> bytes:
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ── Empaquetado ZIP interno ────────────────────────────────────

def _build_inner_zip(pdf_bytes: bytes, bundle_dict: dict) -> bytes:
    """Crea un ZIP en memoria con el PDF y el bundle.json."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("contrato.pdf", pdf_bytes)
        z.writestr("bundle.json", json.dumps(bundle_dict, indent=2, ensure_ascii=False))
    return buf.getvalue()


def _extract_inner_zip(zip_bytes: bytes) -> tuple[bytes, dict]:
    """Extrae PDF y bundle.json de un ZIP en memoria."""
    buf = io.BytesIO(zip_bytes)
    with zipfile.ZipFile(buf, "r") as z:
        pdf_bytes   = z.read("contrato.pdf")
        bundle_dict = json.loads(z.read("bundle.json").decode("utf-8"))
    return pdf_bytes, bundle_dict


# ── API pública ────────────────────────────────────────────────

def encrypt_certified_package(
    pdf_path: pathlib.Path,
    bundle_dict: dict,
    public_key_pem: str,
    output_path: pathlib.Path,
    contract_id: str,
    notario: str,
) -> pathlib.Path:
    """
    Cifra el paquete certificado (PDF + bundle) con cifrado híbrido RSA+AES.

    Args:
        pdf_path      : ruta al PDF sellado
        bundle_dict   : bundle como dict
        public_key_pem: clave pública RSA del notario (PEM)
        output_path   : ruta de salida del paquete .certified
        contract_id   : ID del contrato (para metadatos)
        notario       : nombre del notario (para metadatos)

    Returns:
        output_path
    """
    # 1. Leer PDF
    pdf_bytes = pdf_path.read_bytes()

    # 2. Crear ZIP interno
    inner_zip = _build_inner_zip(pdf_bytes, bundle_dict)

    # 3. Generar clave AES aleatoria y cifrar ZIP
    aes_key          = os.urandom(32)
    aes_nonce, aes_ct = _aes_encrypt(aes_key, inner_zip)

    # 4. Cifrar clave AES con RSA público del notario
    pub_key      = load_public_key_pem(public_key_pem)
    encrypted_key = _rsa_encrypt_key(pub_key, aes_key)

    # 5. Metadatos (no secretos)
    meta = {
        "format":      "HYBRID-CERT-v1",
        "contract_id": contract_id,
        "notario":     notario,
        "fecha":       datetime.now().strftime("%d/%m/%Y %H:%M"),
        "algoritmos":  "RSA-2048-OAEP-SHA256 + AES-256-GCM",
        "nota":        "Descifrar requiere la clave privada RSA del notario."
    }

    # 6. Empaquetar en ZIP externo
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(str(output_path), "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("meta.json",       json.dumps(meta, indent=2, ensure_ascii=False))
        z.writestr("encrypted_key",   encrypted_key)
        z.writestr("aes_nonce",       aes_nonce)
        z.writestr("ciphertext",      aes_ct)

    return output_path


def decrypt_certified_package(
    pkg_path: pathlib.Path,
    private_key_pem: str,
) -> tuple[bytes, dict, dict]:
    """
    Descifra un paquete .certified con la clave privada RSA del notario.

    Args:
        pkg_path       : ruta al archivo .certified
        private_key_pem: clave privada RSA del notario (PEM)

    Returns:
        (pdf_bytes, bundle_dict, meta_dict)

    Lanza:
        ValueError si la clave es incorrecta o el paquete está corrupto
    """
    try:
        with zipfile.ZipFile(str(pkg_path), "r") as z:
            meta          = json.loads(z.read("meta.json").decode("utf-8"))
            encrypted_key = z.read("encrypted_key")
            aes_nonce     = z.read("aes_nonce")
            aes_ct        = z.read("ciphertext")
    except Exception as e:
        raise ValueError(f"No se pudo leer el paquete: {e}")

    if meta.get("format") != "HYBRID-CERT-v1":
        raise ValueError("Formato de paquete no reconocido.")

    # Descifrar clave AES con clave privada RSA
    try:
        priv_key = load_private_key_pem(private_key_pem)
        aes_key  = _rsa_decrypt_key(priv_key, encrypted_key)
    except Exception:
        raise ValueError(
            "No se pudo descifrar con la clave privada proporcionada. "
            "Verifique que sea la clave correcta del notario."
        )

    # Descifrar contenido con AES
    try:
        inner_zip = _aes_decrypt(aes_key, aes_nonce, aes_ct)
    except Exception:
        raise ValueError("Error al descifrar el contenido. El paquete puede estar corrupto.")

    # Extraer PDF y bundle
    pdf_bytes, bundle_dict = _extract_inner_zip(inner_zip)

    return pdf_bytes, bundle_dict, meta