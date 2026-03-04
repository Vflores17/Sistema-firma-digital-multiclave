# src/views/auditor.py
import pathlib
import streamlit as st

from core.hashing import verify_file_hash
from core.bundle import load_bundle, save_bundle, append_signature, get_state, verify_signature_chain, STATE_SIGNED_COMPANY, STATE_CERTIFIED
from core.signatures import (
    load_public_key_pem, verify_signature,
    load_private_key_pem, generate_keypair, export_private_key_pem, export_public_key_pem, sign_data
)
from core.key_manager import obtener_o_generar_clave
from core.encryption import encrypt_file

BASE_DIR = pathlib.Path(__file__).resolve().parents[1].parent
DATA_DIR = BASE_DIR / "data" / "contracts"
KEYS_DIR = BASE_DIR / "keys"
SIGN_KEYS_DIR = KEYS_DIR / "signing"
AES_KEY_PATH = KEYS_DIR / "sistema.key"


def _ensure_dirs():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    SIGN_KEYS_DIR.mkdir(parents=True, exist_ok=True)


def _contracts():
    return sorted([p.name for p in DATA_DIR.iterdir() if p.is_dir()]) if DATA_DIR.exists() else []


def _pdf_path(contract_id: str) -> pathlib.Path:
    return DATA_DIR / contract_id / "contrato.pdf"


def _bundle_path(contract_id: str) -> pathlib.Path:
    return DATA_DIR / contract_id / "bundle.json"


def _pdf_enc_path(contract_id: str) -> pathlib.Path:
    p = _pdf_path(contract_id)
    return p.with_suffix(p.suffix + ".enc")


def _role_key_paths(role: str):
    role = role.lower()
    return SIGN_KEYS_DIR / f"{role}_private.pem", SIGN_KEYS_DIR / f"{role}_public.pem"


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
    if st.session_state.role != "AUDITOR":
        st.error("Acceso restringido")
        st.stop()
    st.subheader("🧾 Vista Auditor / Notario")

    contracts = _contracts()
    if not contracts:
        st.info("No hay contratos todavía.")
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
    ok_chain = verify_signature_chain(bundle)
    st.write("Integridad PDF:", "✅" if ok_pdf else "❌")
    st.write("Cadena de firmas:", "✅" if ok_chain else "❌")

    sigs = bundle.get("signatures", [])
    emp_sig = next((s for s in sigs if s.get("role") == "EMPLEADO"), None)
    com_sig = next((s for s in sigs if s.get("role") == "EMPRESA"), None)

    def verify_entry(entry) -> bool:
        pub = load_public_key_pem(entry["public_key"])
        return verify_signature(pub, bundle["pdf_sha256"].encode("utf-8"), entry["signature"])

    if st.button("Verificar firmas (Empleado + Empresa)"):
        if not emp_sig or not com_sig:
            st.error("Faltan firmas previas.")
        else:
            st.write("Empleado:", "✅" if verify_entry(emp_sig) else "❌")
            st.write("Empresa:", "✅" if verify_entry(com_sig) else "❌")

    if get_state(bundle) == STATE_SIGNED_COMPANY:
        if st.button("Certificar como AUDITOR"):
            priv_pem, pub_pem = _ensure_role_keys("auditor")
            priv = load_private_key_pem(priv_pem)
            sig_b64 = sign_data(priv, bundle["pdf_sha256"].encode("utf-8"))

            bundle = append_signature(
                bundle,
                role="AUDITOR",
                algo="Ed25519",
                public_key=pub_pem,
                signature=sig_b64
            )
            save_bundle(bundle_path, bundle)
            st.success("Contrato CERTIFICADO ✅")
            st.json(bundle)
    else:
        st.caption("Para certificar, el contrato debe estar en estado FIRMADO_EMPRESA.")

    st.divider()
    st.markdown("### 🔐 Cifrado del contrato (AES-256-GCM)")

    if get_state(bundle) == STATE_CERTIFIED:
        aes_key = obtener_o_generar_clave(str(AES_KEY_PATH))

        if st.button("Cifrar contrato.pdf → contrato.pdf.enc"):
            out = encrypt_file(
                pdf_path,
                aes_key,
                output_path=_pdf_enc_path(contract_id),
                contract_id=contract_id,
                pdf_sha256_hex=bundle["pdf_sha256"]
            )
            st.success(f"Generado: {out.name} ✅")
    else:
        st.caption("El cifrado final se habilita cuando el contrato está CERTIFICADO.")