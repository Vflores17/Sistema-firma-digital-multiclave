# src/views/empresa.py

import json
import pathlib
from datetime import datetime

import streamlit as st
from streamlit_drawable_canvas import st_canvas

from core.audit import registrar_evento
from core.bundle import (
    STATE_SIGNED_EMPLOYEE,
    STATE_SIGNED_COMPANY,
    append_signature,
    get_state,
    load_bundle,
    save_bundle,
    verify_signature_chain,
)
from core.hashing import verify_file_hash
from core.signature_verifier import compare_signatures, SSIM_THRESHOLD
from core.pdf_stamp import estampar_firma, LINE_GAP
from core.qr_module import generar_qr
from core.rsa_signatures import (
    generate_rsa_keypair,
    load_rsa_private_key_pem,
    sign_rsa,
)
from core.signatures import (
    export_private_key_pem,
    export_public_key_pem,
)

BASE_DIR     = pathlib.Path(__file__).resolve().parents[1].parent
DATA_DIR     = BASE_DIR / "data" / "contracts"
KEYS_DIR     = BASE_DIR / "keys" / "signing"
SIGN_REF_DIR = BASE_DIR / "keys" / "signatures"

ESTADO_INFO = {
    "CREADO":           ("🟡 Pendiente de firma del empleado",              "warning"),
    "FIRMADO_EMPLEADO": ("🟢 Firmado por empleado — listo para firma empresa", "success"),
    "FIRMADO_EMPRESA":  ("🔵 Firmado por empresa — en espera del auditor",   "info"),
    "CERTIFICADO":      ("✅ Certificado por auditor",                        "success"),
}


def _ensure_dirs():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)


def _contracts():
    return sorted([p.name for p in DATA_DIR.iterdir() if p.is_dir()]) if DATA_DIR.exists() else []


def _pdf_path(contract_id: str) -> pathlib.Path:
    return DATA_DIR / contract_id / "contrato.pdf"


def _pdf_sellado_path(contract_id: str) -> pathlib.Path:
    return DATA_DIR / contract_id / "contrato_firmado.pdf"


def _bundle_path(contract_id: str) -> pathlib.Path:
    return DATA_DIR / contract_id / "bundle.json"


def _qr_path(contract_id: str) -> pathlib.Path:
    return DATA_DIR / contract_id / "qr_empresa.png"


def _ensure_role_keys():
    priv_path = KEYS_DIR / "empresa_private.pem"
    pub_path  = KEYS_DIR / "empresa_public.pem"

    if priv_path.exists() and pub_path.exists():
        return priv_path.read_text(encoding="utf-8"), pub_path.read_text(encoding="utf-8")

    priv, pub = generate_rsa_keypair()
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


def _sign_ref_path(username: str) -> pathlib.Path:
    return SIGN_REF_DIR / f"{username}_referencia.png"


def _mostrar_estado(estado: str):
    etiqueta, tipo = ESTADO_INFO.get(estado, (f"🔘 {estado}", "info"))
    getattr(st, tipo)(f"**Estado del contrato:** {etiqueta}")


def _generar_qr_publico(contract_id: str, bundle: dict, firmantes: list[str]) -> pathlib.Path:
    """
    Genera un QR con información pública del contrato.
    No expone ningún dato del bundle interno.
    """
    datos_publicos = {
        "contract_id":  contract_id,
        "pdf_sha256":   bundle["pdf_sha256"],
        "firmado_por":  firmantes,
        "fecha":        datetime.now().strftime("%d/%m/%Y %H:%M"),
        "estado":       get_state(bundle),
        "nota":         "Verifique el documento calculando el SHA-256 del PDF y comparelo con pdf_sha256."
    }
    qr_data = json.dumps(datos_publicos, ensure_ascii=False)
    qr_path = _qr_path(contract_id)
    generar_qr(qr_data, str(qr_path))
    return qr_path


def render():
    _ensure_dirs()

    if st.session_state.role != "EMPRESA":
        st.error("Acceso restringido")
        st.stop()

    username = st.session_state.user
    st.subheader("🏢 Vista Empresa")

    # ══════════════════════════════════════════════════════════
    # PASO 1 — SELECCIÓN DE CONTRATO
    # ══════════════════════════════════════════════════════════
    st.markdown("### 📁 Paso 1 — Seleccionar contrato")

    contracts = _contracts()
    if not contracts:
        st.info("No hay contratos disponibles todavía.")
        return

    contract_id = st.selectbox(
        "Contrato",
        contracts,
        help="Seleccione el contrato a revisar o firmar."
    )

    pdf_path    = _pdf_path(contract_id)
    bundle_path = _bundle_path(contract_id)

    if not (pdf_path.exists() and bundle_path.exists()):
        st.error("Faltan archivos del contrato (PDF o bundle).")
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
        if ok_pdf:
            st.success("Integridad del PDF ✅")
        else:
            st.error("Integridad del PDF ❌")

    with col2:
        if ok_chain:
            st.success("Cadena de firmas ✅")
        else:
            st.error("Cadena de firmas ❌")

    if not ok_pdf or not ok_chain:
        st.error("⛔ No se puede continuar: el contrato presenta problemas de integridad.")
        return

    st.divider()

    # ══════════════════════════════════════════════════════════
    # CONTRATO AÚN NO FIRMADO POR EMPLEADO
    # ══════════════════════════════════════════════════════════
    if estado == "CREADO":
        st.warning("⏳ Este contrato aún no ha sido firmado por el empleado.")
        return

    # ══════════════════════════════════════════════════════════
    # CONTRATO YA FIRMADO POR EMPRESA O CERTIFICADO
    # ══════════════════════════════════════════════════════════
    if estado in (STATE_SIGNED_COMPANY, "CERTIFICADO"):
        if estado == STATE_SIGNED_COMPANY:
            st.info("✍️ Este contrato ya fue firmado por la empresa. En espera del auditor.")
        else:
            st.success("✅ Este contrato ha sido certificado por el auditor.")

        # Descarga PDF
        pdf_sellado = _pdf_sellado_path(contract_id)
        archivo     = pdf_sellado if pdf_sellado.exists() else pdf_path
        if archivo.exists():
            st.markdown("### 📥 Descargar documento")
            st.download_button(
                label="⬇️ Descargar PDF firmado",
                data=archivo.read_bytes(),
                file_name=f"{contract_id}_firmado.pdf",
                mime="application/pdf",
                use_container_width=True,
            )

        # Mostrar QR si ya existe
        qr_path = _qr_path(contract_id)
        if qr_path.exists():
            st.divider()
            st.markdown("### 📲 Código QR de verificación pública")
            st.caption(
                "Este QR contiene el identificador y hash SHA-256 del contrato. "
                "Cualquier persona puede escanearlo para verificar la autenticidad "
                "del documento sin necesidad de acceder al sistema."
            )
            st.image(str(qr_path), width=200)
        return

    # ══════════════════════════════════════════════════════════
    # PASO 3 — VERIFICACIÓN VISUAL DE IDENTIDAD
    # ══════════════════════════════════════════════════════════
    st.markdown("### ✍️ Paso 3 — Verificación de identidad")
    st.caption("Dibuje su firma para confirmar su identidad antes de firmar digitalmente.")

    verification_key = f"empresa_verificada_{contract_id}"

    # Verificar que tenga firma de referencia registrada
    ref_path = _sign_ref_path(username)
    if not ref_path.exists():
        st.error(
            "⚠️ Su cuenta no tiene una firma de referencia registrada. "
            "Contacte al administrador para completar su registro."
        )
        st.stop()

    st.caption(
        f"Reproduzca su firma registrada con al menos "
        f"**{int(SSIM_THRESHOLD * 100)}% de similitud** para habilitar la firma digital."
    )

    attempt_key = f"canvas_attempt_empresa_{contract_id}"
    fail_key    = f"canvas_fail_empresa_{contract_id}"
    st.session_state.setdefault(attempt_key, 0)
    st.session_state.setdefault(fail_key, False)

    estado_firma = st.session_state.get(verification_key, False)
    fallo_firma  = st.session_state.get(fail_key, False)

    canvas_result = st_canvas(
        fill_color="rgba(255,255,255,0)",
        stroke_width=3,
        stroke_color="#000000",
        background_color="#ffffff",
        height=200,
        width=500,
        drawing_mode="freedraw",
        key=f"canvas_empresa_{contract_id}_{st.session_state[attempt_key]}",
        display_toolbar=False,
    )

    # Indicadores de color bajo el canvas
    if estado_firma:
        st.markdown(
            "<div style='display:flex;gap:8px;margin-top:4px'>"
            "<span style='color:#22c55e;font-size:20px'>●</span>"
            "<span style='color:#22c55e;font-size:20px'>●</span>"
            "<span style='color:#22c55e;font-size:20px'>●</span>"
            "<span style='color:#22c55e;font-size:14px;line-height:24px'>Firma verificada</span>"
            "</div>", unsafe_allow_html=True
        )
    elif fallo_firma:
        st.markdown(
            "<div style='display:flex;gap:8px;margin-top:4px'>"
            "<span style='color:#ef4444;font-size:20px'>●</span>"
            "<span style='color:#ef4444;font-size:20px'>●</span>"
            "<span style='color:#ef4444;font-size:20px'>●</span>"
            "<span style='color:#ef4444;font-size:14px;line-height:24px'>Firma no reconocida — intente nuevamente</span>"
            "</div>", unsafe_allow_html=True
        )
    else:
        st.markdown(
            "<div style='display:flex;gap:8px;margin-top:4px'>"
            "<span style='color:#94a3b8;font-size:20px'>●</span>"
            "<span style='color:#94a3b8;font-size:20px'>●</span>"
            "<span style='color:#94a3b8;font-size:20px'>●</span>"
            "<span style='color:#94a3b8;font-size:14px;line-height:24px'>Dibuje su firma y presione verificar</span>"
            "</div>", unsafe_allow_html=True
        )

    # Botón de limpiar reemplaza el toolbar oculto
    if st.button("🗑️ Limpiar firma", key=f"limpiar_empresa_{contract_id}_{st.session_state[attempt_key]}"):
        st.session_state[attempt_key] += 1
        st.session_state[fail_key]    = False
        st.rerun()

    col_verificar, col_reintentar = st.columns([2, 1])

    with col_verificar:
        if not st.session_state.get(verification_key, False):
            if st.button("🔍 Verificar firma", use_container_width=True):
                img_data = canvas_result.image_data
                if img_data is None or int(img_data.sum()) == 0:
                    st.warning("Debe dibujar su firma antes de verificar.")
                else:
                    aprobada, score = compare_signatures(ref_path, img_data)
                    if aprobada:
                        st.session_state[verification_key] = True
                        st.session_state[fail_key]         = False
                        registrar_evento(
                            f"Empresa '{username}' verificó identidad en contrato "
                            f"'{contract_id}' (score={score})"
                        )
                        st.rerun()
                    else:
                        st.session_state[attempt_key] += 1
                        st.session_state[fail_key]     = True
                        st.rerun()
        else:
            st.success("✅ Identidad verificada")

    with col_reintentar:
        if st.session_state.get(verification_key, False):
            if st.button("🔄 Volver a verificar", use_container_width=True):
                st.session_state[verification_key] = False
                st.session_state[fail_key]         = False
                st.session_state[attempt_key]     += 1
                st.rerun()

    # ══════════════════════════════════════════════════════════
    # PASO 4 — FIRMA DIGITAL (solo si identidad confirmada)
    # ══════════════════════════════════════════════════════════
    if not st.session_state.get(verification_key, False):
        st.divider()
        st.info("🔒 La firma digital se habilitará una vez confirmada su identidad.")
        return

    st.divider()
    st.markdown("### 🔐 Paso 4 — Firma digital del contrato")
    st.caption(f"Se firmará digitalmente **{contract_id}** con clave privada RSA.")

    if st.button("✍️ Firmar contrato digitalmente", use_container_width=True, type="primary"):

        # Firma RSA
        priv_pem, pub_pem = _ensure_role_keys()
        priv    = load_rsa_private_key_pem(priv_pem)
        sig_b64 = sign_rsa(priv, bundle["pdf_sha256"].encode("utf-8"))

        bundle = append_signature(
            bundle,
            role="EMPRESA",
            algo="RSA",
            public_key=pub_pem,
            signature=sig_b64,
        )

        save_bundle(bundle_path, bundle)

        # Estampar sello sobre el PDF (acumula sobre el sellado por empleado si existe)
        pdf_entrada = _pdf_sellado_path(contract_id)
        if not pdf_entrada.exists():
            pdf_entrada = pdf_path

        fecha = datetime.now().strftime("%d/%m/%Y %H:%M")
        estampar_firma(
            pdf_path=pdf_entrada,
            output_path=_pdf_sellado_path(contract_id),
            firmante=f"{username} — {fecha}",
            offset_y=LINE_GAP,   # se coloca encima de la firma del empleado
        )

        # Generar QR con datos públicos
        firmantes = [s["role"] for s in bundle.get("signatures", [])]
        _generar_qr_publico(contract_id, bundle, firmantes)

        registrar_evento(f"Empresa '{username}' firmó digitalmente contrato '{contract_id}'")

        st.session_state[verification_key] = False
        st.rerun()