# src/views/empleado.py

import pathlib

import streamlit as st
from streamlit_drawable_canvas import st_canvas

from core.audit import registrar_evento
from core.bundle import (
    STATE_CREATED,
    STATE_SIGNED_EMPLOYEE,
    append_signature,
    create_bundle,
    get_state,
    load_bundle,
    save_bundle,
)
from core.hashing import sha256_bytes
from core.signature_verifier import compare_signatures, SSIM_THRESHOLD
from core.pdf_stamp import estampar_firma
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
SIGN_REF_DIR = BASE_DIR / "keys" / "signatures"

ESTADO_INFO = {
    "CREADO":           ("🟡 Pendiente de firma",     "warning"),
    "FIRMADO_EMPLEADO": ("🟢 Firmado por empleado",   "success"),
    "FIRMADO_EMPRESA":  ("🔵 Firmado por empresa",    "info"),
    "CERTIFICADO":      ("✅ Certificado por auditor", "success"),
}


def _contracts():
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


def _pdf_sellado_path(contract_id: str) -> pathlib.Path:
    return _contract_dir(contract_id) / "contrato_firmado.pdf"


def _ensure_role_keys(role: str):
    role_lower = role.lower()
    priv_path  = KEYS_DIR / f"{role_lower}_private.pem"
    pub_path   = KEYS_DIR / f"{role_lower}_public.pem"

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


def _reference_image_path(username: str) -> pathlib.Path:
    return SIGN_REF_DIR / f"{username}_referencia.png"


def _mostrar_estado(estado: str):
    etiqueta, tipo = ESTADO_INFO.get(estado, (f"🔘 {estado}", "info"))
    getattr(st, tipo)(f"**Estado del contrato:** {etiqueta}")


def render():
    _ensure_dirs()

    if st.session_state.role != "EMPLEADO":
        st.error("Acceso restringido")
        st.stop()

    username = st.session_state.user
    st.subheader("👨‍💼 Vista Empleado")

    # ── Verificar firma de referencia registrada ───────────────
    ref_path = _reference_image_path(username)
    if not ref_path.exists():
        st.error(
            "⚠️ Su cuenta no tiene una firma de referencia registrada. "
            "Contacte al administrador para completar su registro."
        )
        st.stop()

    # ── Claves de session_state ────────────────────────────────
    # contrato_cargado   : bool  → sección 1 bloqueada
    # contrato_activo    : str   → ID del contrato seleccionado
    # contrato_confirmado: bool  → selectbox bloqueado, canvas habilitado
    # empleado_verificado: bool  → firma visual aprobada

    contrato_cargado    = st.session_state.get("contrato_cargado", False)
    contrato_activo     = st.session_state.get("contrato_activo", None)
    contrato_confirmado = st.session_state.get("contrato_confirmado", False)
    verification_key    = f"empleado_verificado_{contrato_activo}"

    # ══════════════════════════════════════════════════════════
    # PASO 1 — SUBIR CONTRATO
    # ══════════════════════════════════════════════════════════
    st.markdown("### 📄 Paso 1 — Cargar contrato")

    if contrato_cargado:
        # Bloqueado: mostrar resumen de lo cargado
        st.success(f"Contrato **{contrato_activo}** cargado ✅")
        if st.button("🔄 Cargar otro contrato", key="reset_carga"):
            st.session_state["contrato_cargado"]    = False
            st.session_state["contrato_activo"]     = None
            st.session_state["contrato_confirmado"] = False
            st.rerun()

    else:
        contract_name = st.text_input(
            "Nombre / ID del contrato",
            placeholder="Ej: contrato_juan_perez_2026",
            help="Sin espacios ni caracteres especiales.",
        )
        uploaded_file = st.file_uploader("Seleccionar archivo PDF", type=["pdf"])

        if uploaded_file and contract_name.strip():
            contract_id_clean = contract_name.strip().replace(" ", "_")

            if _contract_dir(contract_id_clean).exists():
                st.error(
                    f"Ya existe un contrato con el ID **{contract_id_clean}**. "
                    "Use otro nombre."
                )
            else:
                # Guardar PDF y bundle en disco
                contract_dir = _contract_dir(contract_id_clean)
                contract_dir.mkdir(parents=True, exist_ok=True)

                pdf_bytes  = uploaded_file.getvalue()
                _pdf_path(contract_id_clean).write_bytes(pdf_bytes)

                pdf_sha256 = sha256_bytes(pdf_bytes)
                bundle     = create_bundle(contract_id_clean, pdf_sha256)
                save_bundle(_bundle_path(contract_id_clean), bundle)

                registrar_evento(
                    f"Empleado '{username}' creó contrato '{contract_id_clean}'"
                )

                st.session_state["contrato_activo"]  = contract_id_clean
                st.session_state["contrato_cargado"] = True
                st.rerun()

    st.divider()

    # ══════════════════════════════════════════════════════════
    # PASO 2 — CONTRATO ACTIVO (selectbox deshabilitado)
    # ══════════════════════════════════════════════════════════
    st.markdown("### 📁 Paso 2 — Contrato activo")

    contracts = _contracts()

    if not contracts:
        st.info("No hay contratos disponibles. Suba uno primero.")
        return

    # Resolver índice actual
    if contrato_activo not in contracts:
        contrato_activo = contracts[0]
        st.session_state["contrato_activo"] = contrato_activo

    # Selectbox siempre deshabilitado — el contrato queda fijo al cargarse
    contract_id = st.selectbox(
        "Contrato seleccionado",
        contracts,
        index=contracts.index(contrato_activo),
        disabled=True,
        help="El contrato queda fijo una vez cargado.",
    )

    # A partir de aquí el contrato está confirmado y bloqueado
    bundle_path = _bundle_path(contract_id)
    pdf_path    = _pdf_path(contract_id)

    if not bundle_path.exists():
        st.error("No se encontró el bundle del contrato.")
        return

    bundle = load_bundle(bundle_path)
    estado = get_state(bundle)

    _mostrar_estado(estado)
    st.divider()

    # ══════════════════════════════════════════════════════════
    # CONTRATO YA FIRMADO — mensaje + descarga
    # ══════════════════════════════════════════════════════════
    if estado != STATE_CREATED:
        recien_firmado = st.session_state.get("contrato_firmado_ok") == contract_id

        if recien_firmado:
            st.success("🎉 ¡Contrato firmado exitosamente!")
            st.session_state.pop("contrato_firmado_ok", None)
        elif estado == STATE_SIGNED_EMPLOYEE:
            st.info("✍️ Usted ya firmó este contrato. Está en espera de la firma de la empresa.")
        else:
            st.success("✅ Este contrato completó el flujo de firmas.")

        pdf_sellado = _pdf_sellado_path(contract_id)
        archivo_descarga = pdf_sellado if pdf_sellado.exists() else pdf_path

        if archivo_descarga.exists():
            st.markdown("### 📥 Descargar documento")
            st.download_button(
                label="⬇️ Descargar PDF firmado",
                data=archivo_descarga.read_bytes(),
                file_name=f"{contract_id}_firmado.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        return

    # ══════════════════════════════════════════════════════════
    # PASO 3 — VERIFICACIÓN DE IDENTIDAD (canvas habilitado)
    # ══════════════════════════════════════════════════════════
    st.markdown("### ✍️ Paso 3 — Verificación de identidad")
    st.caption(
        f"Reproduzca su firma registrada con al menos "
        f"**{int(SSIM_THRESHOLD * 100)}% de similitud** para habilitar la firma digital."
    )

    # canvas_attempt_key controla cuántas veces se ha intentado — cambiarlo limpia el canvas
    attempt_key  = f"canvas_attempt_empleado_{contract_id}"
    fail_key     = f"canvas_fail_empleado_{contract_id}"
    st.session_state.setdefault(attempt_key, 0)
    st.session_state.setdefault(fail_key, False)

    # Indicadores de estado bajo el canvas
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
        key=f"canvas_empleado_{contract_id}_{st.session_state[attempt_key]}",
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
    if st.button("🗑️ Limpiar firma", key=f"limpiar_empleado_{contract_id}_{st.session_state[attempt_key]}"):
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
                            f"Empleado '{username}' verificó identidad "
                            f"en contrato '{contract_id}' (score={score})"
                        )
                        st.rerun()
                    else:
                        # Limpiar canvas incrementando el attempt
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
    # PASO 4 — FIRMA DIGITAL
    # ══════════════════════════════════════════════════════════
    if not st.session_state.get(verification_key, False):
        st.divider()
        st.info("🔒 La firma digital se habilitará una vez verificada su identidad.")
        return

    st.divider()
    st.markdown("### 🔐 Paso 4 — Firma digital del contrato")
    st.caption(
        f"Se firmará digitalmente **{contract_id}** con su clave privada Ed25519."
    )

    if st.button("✍️ Firmar contrato digitalmente", use_container_width=True, type="primary"):
        priv_pem, pub_pem = _ensure_role_keys("empleado")
        priv    = load_private_key_pem(priv_pem)
        sig_b64 = sign_data(priv, bundle["pdf_sha256"].encode("utf-8"))

        bundle = append_signature(
            bundle,
            role="EMPLEADO",
            algo="Ed25519",
            public_key=pub_pem,
            signature=sig_b64,
        )

        save_bundle(bundle_path, bundle)

        # Estampar sello en el PDF
        estampar_firma(
            pdf_path=pdf_path,
            output_path=_pdf_sellado_path(contract_id),
            firmante=username,
            rol="EMPLEADO",
            sha256_hex=bundle["pdf_sha256"],
        )

        registrar_evento(
            f"Empleado '{username}' firmó digitalmente contrato '{contract_id}'"
        )

        st.session_state[verification_key] = False
        st.session_state["contrato_firmado_ok"] = contract_id
        st.rerun()