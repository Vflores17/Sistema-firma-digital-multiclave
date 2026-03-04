# src/core/bundle.py

"""
bundle.py

Maneja la creación, carga, modificación y guardado del bundle.json
que contiene toda la información del contrato firmado.
"""

import json
import pathlib
import hashlib
from datetime import datetime


# Estados posibles del contrato
STATE_CREATED = "CREADO"
STATE_SIGNED_EMPLOYEE = "FIRMADO_EMPLEADO"
STATE_SIGNED_COMPANY = "FIRMADO_EMPRESA"
STATE_CERTIFIED = "CERTIFICADO"


def _timestamp():
    """
    Devuelve timestamp ISO8601.
    """
    return datetime.utcnow().isoformat() + "Z"


def create_bundle(contract_id: str, pdf_sha256: str) -> dict:
    """
    Crea un bundle inicial.

    Args:
        contract_id
        pdf_sha256

    Returns:
        dict
    """

    return {
        "contract_id": contract_id,
        "pdf_sha256": pdf_sha256,
        "state": STATE_CREATED,
        "created_at": _timestamp(),
        "signatures": []
    }


def load_bundle(path: str | pathlib.Path) -> dict:
    """
    Carga bundle desde archivo.
    """

    path = pathlib.Path(path)

    if not path.exists():
        raise FileNotFoundError("bundle.json no encontrado")

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_bundle(path: str | pathlib.Path, bundle: dict):
    """
    Guarda bundle en archivo.
    """

    path = pathlib.Path(path)

    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=4)


def _hash_signature(signature: dict) -> str:
    """
    Genera hash de una firma para encadenar firmas.
    """

    data = json.dumps(signature, sort_keys=True).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def append_signature(
        bundle: dict,
        role: str,
        algo: str,
        public_key: str,
        signature: str
) -> dict:
    """
    Agrega una firma al bundle.

    Args:
        role
        algo
        public_key
        signature

    Returns:
        bundle actualizado
    """

    prev_hash = None

    if bundle["signatures"]:
        prev_hash = _hash_signature(bundle["signatures"][-1])

    entry = {
        "role": role,
        "algorithm": algo,
        "public_key": public_key,
        "signature": signature,
        "timestamp": _timestamp(),
        "prev_signature_hash": prev_hash
    }

    bundle["signatures"].append(entry)

    # actualizar estado
    if role == "EMPLEADO":
        bundle["state"] = STATE_SIGNED_EMPLOYEE

    elif role == "EMPRESA":
        bundle["state"] = STATE_SIGNED_COMPANY

    elif role == "AUDITOR":
        bundle["state"] = STATE_CERTIFIED

    return bundle


def get_state(bundle: dict) -> str:
    """
    Devuelve el estado actual del contrato.
    """

    return bundle.get("state", STATE_CREATED)


def verify_signature_chain(bundle: dict) -> bool:
    """
    Verifica que la cadena de firmas no haya sido alterada.
    """

    signatures = bundle.get("signatures", [])

    if not signatures:
        return True

    prev_hash = None

    for sig in signatures:

        if sig["prev_signature_hash"] != prev_hash:
            return False

        prev_hash = _hash_signature(sig)

    return True