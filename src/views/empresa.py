# src/views/empresa.py
import base64
import pathlib

import streamlit as st
from streamlit_drawable_canvas import st_canvas

from core.audit import registrar_evento
from core.bundle import (
    STATE_SIGNED_EMPLOYEE,
    append_signature,
    get_state,
    load_bundle,
    save_bundle,
    verify_signature_chain,
)
from core.hashing import verify_file_hash
from core.qr_module import generar_qr
from core.rsa_signatures import (
    generate_rsa_keypair,
    load_rsa_private_key_pem,
    sign_rsa,
)
from core.signatures import (
    export_private_key_pem,
    export_public_key_pem,
    load_public_key_pem,
    verify_signature,
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
        return (
            priv_path.read_text(encoding="utf-8"),
            pub_path.read_text(encoding="utf-8"),
        )

    if role.lower() == "empresa":
        priv, pub = generate_rsa_keypair()
    else:
        raise ValueError("Este módulo solo genera llaves RSA para EMPRESA.")

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

    if st.session_state.role != "EMPRESA":
        st.error("Acceso restringido")
        st.stop()

    st.subheader("🏢 Vista Empresa")

    contracts = _contracts()
    if not contracts:
        st.info("No hay contratos todavía. Créelo desde la vista Empleado.")
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

    if not emp_sig:
        st.warning("Aún no existe firma del empleado.")
        st.json(bundle)
        return

    if st.button("Verificar firma del EMPLEADO"):
        pub = load_public_key_pem(emp_sig["public_key"])
        ok = verify_signature(
            pub,
            bundle["pdf_sha256"].encode("utf-8"),
            emp_sig["signature"],
        )
        st.write("Firma empleado:", "✅ Válida" if ok else "❌ Inválida")

    if get_state(bundle) != STATE_SIGNED_EMPLOYEE:
        st.caption("Para firmar como empresa, el contrato debe estar en estado FIRMADO_EMPLEADO.")
        return

    st.divider()
    st.subheader("✍️ Verificación de identidad - Empresa")

    verification_key = f"empresa_identidad_verificada_{contract_id}"
    visual_signature_key = f"firma_visual_empresa_{contract_id}"

    canvas_result = st_canvas(
        fill_color="rgba(0,0,0,0)",
        stroke_width=3,
        stroke_color="#000000",
        background_color="#ffffff",
        height=200,
        width=500,
        drawing_mode="freedraw",
        key=f"empresa_firma_{contract_id}",
    )

    if not st.session_state.get(verification_key, False):
        if st.button("Verificar identidad empresa"):
            if canvas_result.image_data is None:
                st.error("Debe realizar una firma visual.")
                st.stop()

            firma_bytes = canvas_result.image_data.tobytes()
            firma_visual_b64 = base64.b64encode(firma_bytes).decode("utf-8")

            st.session_state[visual_signature_key] = firma_visual_b64
            st.session_state[verification_key] = True

            st.success("✅ Identidad empresa verificada")
            st.rerun()

    if st.session_state.get(verification_key, False):
        st.success("Identidad confirmada 🔐")

        if st.button("Firmar contrato digitalmente (Empresa)"):
            priv_pem, pub_pem = _ensure_role_keys("empresa")
            priv = load_rsa_private_key_pem(priv_pem)

            sig_b64 = sign_rsa(
                priv,
                bundle["pdf_sha256"].encode("utf-8"),
            )

            bundle = append_signature(
                bundle,
                role="EMPRESA",
                algo="RSA",
                public_key=pub_pem,
                signature=sig_b64,
            )

            bundle["firma_visual_empresa"] = st.session_state.get(visual_signature_key)

            save_bundle(bundle_path, bundle)

            registrar_evento(f"Empresa firmó contrato {contract_id}")

            qr_path = DATA_DIR / contract_id / "qr.png"
            generar_qr(bundle["pdf_sha256"], str(qr_path))

            st.success("Firma de empresa agregada ✅")
            st.image(str(qr_path), caption="QR del contrato")
            st.json(bundle)