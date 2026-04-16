# src/views/notario.py

import pathlib

import streamlit as st

from core.audit import registrar_evento
from core.bundle import (
    STATE_SIGNED_COMPANY,
    STATE_CERTIFIED,
    append_signature,
    get_state,
    load_bundle,
    save_bundle,
    verify_signature_chain,
)
from core.face_verifier import verify_face_from_upload, FACE_THRESHOLD
from core.hybrid_encryption import (
    generate_rsa_keypair,
    export_private_key_pem as export_rsa_private_pem,
    export_public_key_pem  as export_rsa_public_pem,
    encrypt_certified_package,
    PKG_EXT,
)
from core.hashing import verify_file_hash
from core.pdf_stamp import estampar_firma, LINE_GAP
from core.signatures import (
    export_private_key_pem,
    export_public_key_pem,
    generate_keypair,
    load_private_key_pem,
    sign_data,
)

BASE_DIR     = pathlib.Path(__file__).resolve().parents[1].parent
DATA_DIR     = BASE_DIR / "data" / "contracts"
KEYS_DIR     = BASE_DIR / "keys" / "signing"
FACE_REF_DIR = BASE_DIR / "keys" / "faces"


def _face_enc_path(username: str):
    return FACE_REF_DIR / f"{username}_encoding.bin"


def _certified_pkg_path(contract_id: str) -> pathlib.Path:
    return DATA_DIR / contract_id / f"{contract_id}{PKG_EXT}"


ESTADO_INFO = {
    "CREADO":           ("🟡 Pendiente de firma del empleado",                "warning"),
    "FIRMADO_EMPLEADO": ("🟠 Firmado por empleado — falta firma de empresa",  "warning"),
    "FIRMADO_EMPRESA":  ("🟢 Listo para certificación del notario",           "success"),
    "CERTIFICADO":      ("✅ Certificado",                                     "success"),
}


def _contracts():
    return sorted([p.name for p in DATA_DIR.iterdir() if p.is_dir()]) if DATA_DIR.exists() else []


def _pdf_path(contract_id: str) -> pathlib.Path:
    return DATA_DIR / contract_id / "contrato.pdf"


def _pdf_sellado_path(contract_id: str) -> pathlib.Path:
    return DATA_DIR / contract_id / "contrato_firmado.pdf"


def _bundle_path(contract_id: str) -> pathlib.Path:
    return DATA_DIR / contract_id / "bundle.json"


def _face_ref_path(username: str) -> pathlib.Path:
    return FACE_REF_DIR / f"{username}_rostro.png"


def _ensure_role_keys():
    priv_path = KEYS_DIR / "notario_private.pem"
    pub_path  = KEYS_DIR / "notario_public.pem"

    if priv_path.exists() and pub_path.exists():
        return priv_path.read_text(encoding="utf-8"), pub_path.read_text(encoding="utf-8")

    priv, pub = generate_keypair()
    priv_pem  = export_private_key_pem(priv)
    pub_pem   = export_public_key_pem(pub)

    priv_path.write_text(priv_pem, encoding="utf-8")
    pub_path.write_text(pub_pem, encoding="utf-8")

    try:
        import os
        os.chmod(priv_path, 0o600)
        os.chmod(pub_path, 0o644)
    except Exception:
        pass

    return priv_pem, pub_pem


def _mostrar_estado(estado: str):
    etiqueta, tipo = ESTADO_INFO.get(estado, (f"🔘 {estado}", "info"))
    getattr(st, tipo)(f"**Estado del contrato:** {etiqueta}")


def render():
    if st.session_state.role != "NOTARIO":
        st.error("Acceso restringido")
        st.stop()

    username = st.session_state.user
    st.subheader("⚖️ Vista Notario")

    # ── Verificar rostro de referencia ────────────────────────
    face_enc = _face_enc_path(username)
    if not face_enc.exists():
        st.error(
            "⚠️ Su cuenta no tiene un rostro de referencia registrado. "
            "Contacte al administrador para completar su registro."
        )
        st.stop()

    # ══════════════════════════════════════════════════════════
    # PASO 1 — SELECCIONAR CONTRATO
    # ══════════════════════════════════════════════════════════
    st.markdown("### 📁 Paso 1 — Seleccionar contrato")

    contracts = _contracts()
    if not contracts:
        st.info("No hay contratos disponibles.")
        return

    contract_id = st.selectbox("Contrato", contracts)

    pdf_path    = _pdf_path(contract_id)
    bundle_path = _bundle_path(contract_id)

    if not (pdf_path.exists() and bundle_path.exists()):
        st.error("Faltan archivos del contrato.")
        return

    bundle = load_bundle(bundle_path)
    estado = get_state(bundle)

    _mostrar_estado(estado)
    st.divider()

    # ══════════════════════════════════════════════════════════
    # PASO 2 — VERIFICACIÓN DE INTEGRIDAD
    # ══════════════════════════════════════════════════════════
    st.markdown("### 🔍 Paso 2 — Verificación de integridad")

    ok_pdf   = verify_file_hash(pdf_path, bundle["pdf_sha256"])
    ok_chain = verify_signature_chain(bundle)

    col1, col2 = st.columns(2)
    with col1:
        st.success("Integridad del PDF ✅") if ok_pdf else st.error("Integridad del PDF ❌")
    with col2:
        st.success("Cadena de firmas ✅") if ok_chain else st.error("Cadena de firmas ❌")

    if not ok_pdf or not ok_chain:
        st.error("⛔ No se puede continuar: el contrato presenta problemas de integridad.")
        return

    st.divider()

    # ── Contrato no listo para certificar ─────────────────────
    if estado != STATE_SIGNED_COMPANY:
        if estado == "CERTIFICADO":
            st.success("✅ Este contrato ya fue certificado.")

            # ── Descarga clave privada RSA (solo justo después de certificar) ──
            if st.session_state.get("notario_rsa_contract") == contract_id:
                rsa_priv_pem = st.session_state.get("notario_rsa_priv_pem", "")
                if rsa_priv_pem:
                    st.warning(
                        "⚠️ **Descargue la clave privada ahora.** "
                        "Es la única forma de descifrar el paquete certificado. "
                        "No se volverá a mostrar."
                    )
                    st.download_button(
                        label="⬇️ Descargar clave privada RSA (.pem)",
                        data=rsa_priv_pem.encode(),
                        file_name=f"{contract_id}_notario_private.pem",
                        mime="application/x-pem-file",
                        use_container_width=True,
                        key="dl_priv_key",
                    )

            # ── Descarga paquete certificado ──────────────────────
            pkg_path = _certified_pkg_path(contract_id)
            if pkg_path.exists():
                st.markdown("### 📥 Descargar paquete certificado")
                st.download_button(
                    label=f"⬇️ Descargar paquete certificado ({PKG_EXT})",
                    data=pkg_path.read_bytes(),
                    file_name=pkg_path.name,
                    mime="application/octet-stream",
                    use_container_width=True,
                    key="dl_pkg_cert",
                )

            # ── Descarga PDF sellado ───────────────────────────────
            pdf_sellado = _pdf_sellado_path(contract_id)
            archivo     = pdf_sellado if pdf_sellado.exists() else pdf_path
            if archivo.exists():
                st.download_button(
                    label="⬇️ Descargar PDF certificado",
                    data=archivo.read_bytes(),
                    file_name=f"{contract_id}_certificado.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                    key="dl_pdf_cert",
                )
        else:
            st.warning("⏳ Este contrato aún no completó las firmas previas.")
        return

    # ══════════════════════════════════════════════════════════
    # PASO 3 — AUTENTICACIÓN FACIAL
    # ══════════════════════════════════════════════════════════
    st.markdown("### 📷 Paso 3 — Autenticación facial")
    st.caption(
        "Colóquese frente a la cámara con buena iluminación y presione el botón de captura."
    )

    face_key = f"notario_face_ok_{contract_id}"

    if not st.session_state.get(face_key, False):
        st.info("📷 Centre su rostro en la cámara y presione el botón de captura.")
        foto = st.camera_input("Capturar rostro para autenticación", key=f"notario_face_{contract_id}")

        if foto:
            try:
                aprobado, score = verify_face_from_upload(face_enc, foto)

                if aprobado:
                    st.session_state[face_key] = True
                    registrar_evento(
                        f"Notario '{username}' autenticado facialmente "
                        f"en contrato '{contract_id}' (score={score})"
                    )
                    st.rerun()
                else:
                    st.error("❌ Identidad no verificada. Intente nuevamente.")
            except Exception as e:
                st.error(f"Error al procesar la captura: {e}")
    else:
        st.success("✅ Identidad verificada por reconocimiento facial")
        if st.button("🔄 Volver a verificar", use_container_width=True):
            st.session_state[face_key] = False
            st.rerun()

    # ══════════════════════════════════════════════════════════
    # PASO 4 — CERTIFICACIÓN
    # ══════════════════════════════════════════════════════════
    if not st.session_state.get(face_key, False):
        st.divider()
        st.info("🔒 La certificación se habilitará una vez verificada su identidad facial.")
        return

    st.divider()
    st.markdown("### 🔐 Paso 4 — Certificación del contrato")
    st.caption(
        f"Se certificará **{contract_id}** con su clave privada Ed25519. "
        "Esta acción es definitiva e irreversible."
    )

    if st.button("⚖️ Certificar contrato", use_container_width=True, type="primary"):
        from datetime import datetime
        fecha = datetime.now().strftime("%d/%m/%Y %H:%M")

        # ── Firma Ed25519 ──────────────────────────────────────
        priv_pem, pub_pem = _ensure_role_keys()
        priv    = load_private_key_pem(priv_pem)
        sig_b64 = sign_data(priv, bundle["pdf_sha256"].encode("utf-8"))

        bundle = append_signature(
            bundle,
            role="AUDITOR",
            algo="Ed25519",
            public_key=pub_pem,
            signature=sig_b64,
        )
        save_bundle(bundle_path, bundle)

        # ── Sello en PDF ───────────────────────────────────────
        pdf_entrada = _pdf_sellado_path(contract_id)
        if not pdf_entrada.exists():
            pdf_entrada = pdf_path

        estampar_firma(
            pdf_path=pdf_entrada,
            output_path=_pdf_sellado_path(contract_id),
            firmante=f"{username} (Notario) — {fecha}",
            offset_y=LINE_GAP * 2,
        )

        # ── Cifrado híbrido RSA+AES ────────────────────────────
        # Generar par de claves RSA único para este contrato
        rsa_priv, rsa_pub = generate_rsa_keypair()
        rsa_priv_pem      = export_rsa_private_pem(rsa_priv)
        rsa_pub_pem       = export_rsa_public_pem(rsa_pub)

        encrypt_certified_package(
        pdf_path=_pdf_path(contract_id),
        bundle_dict=bundle,
        public_key_pem=rsa_pub_pem,
        output_path=_certified_pkg_path(contract_id),
        contract_id=contract_id,
        notario=username,
        )

        # Guardar clave privada RSA en session para descarga inmediata
        st.session_state["notario_rsa_priv_pem"] = rsa_priv_pem
        st.session_state["notario_rsa_contract"]  = contract_id

        registrar_evento(
            f"Notario '{username}' certificó y cifró contrato '{contract_id}'"
        )

        st.session_state[face_key] = False
        st.session_state["notario_certificado_ok"] = contract_id
        st.rerun()