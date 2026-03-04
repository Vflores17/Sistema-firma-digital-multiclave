# src/views/empresa.py
import pathlib
import streamlit as st

from core.hashing import verify_file_hash
from core.bundle import load_bundle, save_bundle, append_signature, get_state, verify_signature_chain, STATE_SIGNED_EMPLOYEE
from core.signatures import (
    load_public_key_pem, verify_signature,
    load_private_key_pem, generate_keypair, export_private_key_pem, export_public_key_pem, sign_data
)

BASE_DIR = pathlib.Path(__file__).resolve().parents[1].parent
DATA_DIR = BASE_DIR / "data" / "contracts"
KEYS_DIR = BASE_DIR / "keys" / "signing"


def _ensure_dirs():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)


def _contracts():
    return sorted([p.name for p in DATA_DIR.iterdir() if p.is_dir()]) if DATA_DIR.exists() else []


def _pdf_path(contract_id: str) -> pathlib.Path:
    return DATA_DIR / contract_id / "contrato.pdf"


def _bundle_path(contract_id: str) -> pathlib.Path:
    return DATA_DIR / contract_id / "bundle.json"


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
    if st.session_state.role != "EMPRESA":
        st.error("Acceso restringido")
        st.stop()

    st.subheader("🏢 Vista Empresa")

    contracts = _contracts()
    if not contracts:
        st.info("No hay contratos todavía. Créalo desde la vista Empleado.")
        return

    contract_id = st.selectbox("Seleccionar contrato", contracts)

    pdf_path = _pdf_path(contract_id)
    bundle_path = _bundle_path(contract_id)

    if not (pdf_path.exists() and bundle_path.exists()):
        st.error("Falta contrato.pdf o bundle.json")
        return

    bundle = load_bundle(bundle_path)
    st.write("Estado actual:", get_state(bundle))

    ok_pdf = verify_file_hash(pdf_path, bundle["pdf_sha256"])
    st.write("Integridad PDF:", "✅" if ok_pdf else "❌")

    ok_chain = verify_signature_chain(bundle)
    st.write("Cadena de firmas:", "✅" if ok_chain else "❌")

    sigs = bundle.get("signatures", [])
    emp_sig = next((s for s in sigs if s.get("role") == "EMPLEADO"), None)
    if not emp_sig:
        st.warning("Aún no existe firma del empleado.")
        st.json(bundle)
        return

    if st.button("Verificar firma del EMPLEADO"):
        pub = load_public_key_pem(emp_sig["public_key"])
        ok = verify_signature(pub, bundle["pdf_sha256"].encode("utf-8"), emp_sig["signature"])
        st.write("Firma empleado:", "✅ Válida" if ok else "❌ Inválida")

    if get_state(bundle) != STATE_SIGNED_EMPLOYEE:
        st.caption("Para firmar como empresa, el contrato debe estar en estado FIRMADO_EMPLEADO.")
        return

    if st.button("Firmar como EMPRESA"):
        priv_pem, pub_pem = _ensure_role_keys("empresa")
        priv = load_private_key_pem(priv_pem)
        sig_b64 = sign_data(priv, bundle["pdf_sha256"].encode("utf-8"))

        bundle = append_signature(
            bundle,
            role="EMPRESA",
            algo="Ed25519",
            public_key=pub_pem,
            signature=sig_b64
        )
        save_bundle(bundle_path, bundle)
        st.success("Firma de empresa agregada ✅")
        st.json(bundle)