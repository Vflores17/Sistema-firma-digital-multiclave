# src/views/empleado.py
import pathlib

import streamlit as st
from PIL import Image
from streamlit_drawable_canvas import st_canvas

from core.audit import registrar_evento
from core.bundle import (
    STATE_CREATED,
    append_signature,
    create_bundle,
    get_state,
    load_bundle,
    save_bundle,
)
from core.hashing import sha256_bytes
from core.signatures import (
    export_private_key_pem,
    export_public_key_pem,
    generate_keypair,
    load_private_key_pem,
    sign_data,
)

BASE_DIR = pathlib.Path(__file__).resolve().parents[1].parent
DATA_DIR = BASE_DIR / "data" / "contracts"
KEYS_DIR = BASE_DIR / "keys" / "signing"


def _contracts():
    """Lista los IDs de contratos existentes."""
    if not DATA_DIR.exists():
        return []

    return sorted([p.name for p in DATA_DIR.iterdir() if p.is_dir()])


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
        return (
            priv_path.read_text(encoding="utf-8"),
            pub_path.read_text(encoding="utf-8"),
        )

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

    if st.session_state.role != "EMPLEADO":
        st.error("Acceso restringido")
        st.stop()

    st.subheader("👨‍💼 Vista Empleado")

    # ==============================
    # CREAR CONTRATO
    # ==============================
    st.markdown("### 📄 Crear nuevo contrato")

    uploaded_file = st.file_uploader("Subir contrato PDF", type=["pdf"])
    new_contract_id = st.text_input("ID del contrato")

    if uploaded_file and new_contract_id:
        pdf_bytes = uploaded_file.getvalue()

        contract_dir = _contract_dir(new_contract_id)
        contract_dir.mkdir(parents=True, exist_ok=True)

        pdf_path = _pdf_path(new_contract_id)
        pdf_path.write_bytes(pdf_bytes)

        pdf_sha256 = sha256_bytes(pdf_bytes)
        bundle = create_bundle(new_contract_id, pdf_sha256)
        save_bundle(_bundle_path(new_contract_id), bundle)

        st.success("Contrato creado ✅")

    # ==============================
    # SELECCIONAR CONTRATO
    # ==============================
    contracts = _contracts()
    if not contracts:
        st.info("No hay contratos disponibles.")
        return

    contract_id = st.selectbox("Seleccionar contrato", contracts)

    pdf_path = _pdf_path(contract_id)
    bundle_path = _bundle_path(contract_id)

    if not bundle_path.exists():
        st.error("No se encontró el bundle del contrato.")
        return

    bundle = load_bundle(bundle_path)
    st.write("Estado actual:", get_state(bundle))

    # ==============================
    # VERIFICACIÓN DE IDENTIDAD
    # ==============================
    st.markdown("## ✍️ Firme aquí para verificar su identidad")

    canvas_result = st_canvas(
        fill_color="rgba(255,255,255,0)",
        stroke_width=3,
        stroke_color="#000000",
        background_color="#ffffff",
        height=200,
        width=500,
        drawing_mode="freedraw",
        key=f"canvas_empleado_{contract_id}",
    )

    verification_key = f"empleado_verificado_{contract_id}"

    if st.button("Guardar firma visual"):
        if canvas_result.image_data is not None:
            img = Image.fromarray(canvas_result.image_data.astype("uint8"))
            firma_path = _contract_dir(contract_id) / "firma_empleado.png"
            img.save(firma_path)

            st.session_state[verification_key] = True

            registrar_evento(
                f"Empleado verificó identidad en contrato {contract_id}"
            )

            st.success("Identidad verificada ✅")
        else:
            st.warning("Debe dibujar una firma.")

    # ==============================
    # FIRMA DIGITAL
    # ==============================
    if not st.session_state.get(verification_key, False):
        st.info("Primero debe verificar su identidad con la firma visual.")
        return

    if get_state(bundle) != STATE_CREATED:
        st.caption("El contrato ya fue firmado o avanzó de estado.")
        st.json(bundle)
        return

    st.markdown("## 🔐 Firma digital del contrato")

    if st.button("Firmar digitalmente como EMPLEADO"):
        priv_pem, pub_pem = _ensure_role_keys("empleado")
        priv = load_private_key_pem(priv_pem)

        sig_b64 = sign_data(
            priv,
            bundle["pdf_sha256"].encode("utf-8"),
        )

        bundle = append_signature(
            bundle,
            role="EMPLEADO",
            algo="Ed25519",
            public_key=pub_pem,
            signature=sig_b64,
        )

        save_bundle(bundle_path, bundle)

        registrar_evento(
            f"Empleado firmó digitalmente contrato {contract_id}"
        )

        st.success("Contrato firmado digitalmente ✅")
        st.json(bundle)