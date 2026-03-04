# src/views/empleado.py
import pathlib
import streamlit as st

from core.hashing import sha256_bytes
from core.bundle import create_bundle, load_bundle, save_bundle, append_signature, get_state, STATE_CREATED
from core.signatures import load_private_key_pem, load_public_key_pem, sign_data, generate_keypair, export_private_key_pem, export_public_key_pem

BASE_DIR = pathlib.Path(__file__).resolve().parents[1].parent
DATA_DIR = BASE_DIR / "data" / "contracts"
KEYS_DIR = BASE_DIR / "keys" / "signing"


def _ensure_dirs():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)


def _contract_dir(contract_id: str) -> pathlib.Path:
    return DATA_DIR / contract_id


def _pdf_path(contract_id: str) -> pathlib.Path:
    return _contract_dir(contract_id) / "contrato.pdf"


def _bundle_path(contract_id: str) -> pathlib.Path:
    return _contract_dir(contract_id) / "bundle.json"


def _role_key_paths(role: str):
    role = role.lower()
    return KEYS_DIR / f"{role}_private.pem", KEYS_DIR / f"{role}_public.pem"


def _ensure_role_keys(role: str):
    priv_path, pub_path = _role_key_paths(role)

    if priv_path.exists() and pub_path.exists():
        return priv_path.read_text(encoding="utf-8"), pub_path.read_text(encoding="utf-8")

    priv, pub = generate_keypair()
    priv_pem = export_private_key_pem(priv)
    pub_pem = export_public_key_pem(pub)

    priv_path.write_text(priv_pem, encoding="utf-8")
    pub_path.write_text(pub_pem, encoding="utf-8")

    try:
        import os
        os.chmod(priv_path, 0o600)
        os.chmod(pub_path, 0o644)
    except Exception:
        pass

    return priv_pem, pub_pem


def render():
    _ensure_dirs()
    # 🔒 CONTROL DE ACCESO
    if st.session_state.role != "EMPLEADO":
        st.error("Acceso restringido")
        st.stop()
        
    st.subheader("👤 Vista Empleado / Proveedor")

    contract_id = st.text_input("Contract ID (ej: CT-2026-0001)", value="CT-2026-0001")
    uploaded_pdf = st.file_uploader("Subir contrato PDF", type=["pdf"])

    if uploaded_pdf:
        pdf_bytes = uploaded_pdf.getvalue()
        pdf_hash = sha256_bytes(pdf_bytes)
        st.info(f"SHA-256 del PDF: {pdf_hash}")

        if st.button("Guardar contrato y crear bundle"):
            cdir = _contract_dir(contract_id)
            cdir.mkdir(parents=True, exist_ok=True)

            _pdf_path(contract_id).write_bytes(pdf_bytes)

            bundle = create_bundle(contract_id, pdf_hash)
            save_bundle(_bundle_path(contract_id), bundle)
            st.success("Contrato guardado y bundle creado ✅")

    # Firmar si ya existe
    if _pdf_path(contract_id).exists() and _bundle_path(contract_id).exists():
        bundle = load_bundle(_bundle_path(contract_id))
        st.write("Estado actual:", get_state(bundle))

        if get_state(bundle) != STATE_CREATED:
            st.warning("Este contrato ya avanzó de estado.")
            st.json(bundle)
            return

        if st.button("Firmar como EMPLEADO"):
            priv_pem, pub_pem = _ensure_role_keys("empleado")
            priv = load_private_key_pem(priv_pem)

            signature_b64 = sign_data(priv, bundle["pdf_sha256"].encode("utf-8"))

            bundle = append_signature(
                bundle,
                role="EMPLEADO",
                algo="Ed25519",
                public_key=pub_pem,
                signature=signature_b64
            )
            save_bundle(_bundle_path(contract_id), bundle)

            st.success("Firma del empleado agregada ✅")
            st.json(bundle)
    else:
        st.caption("Subí un PDF y creá el bundle para poder firmar.")