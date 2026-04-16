# src/views/auditor.py

import json
import pathlib

import streamlit as st

from core.bundle import (
    get_state,
    load_bundle,
    verify_signature_chain,
)
from core.hashing import verify_file_hash
from core.signatures import load_public_key_pem, verify_signature

BASE_DIR = pathlib.Path(__file__).resolve().parents[1].parent
DATA_DIR = BASE_DIR / "data" / "contracts"
AUDIT_LOG = BASE_DIR / "data" / "audit.log"

ESTADO_INFO = {
    "CREADO":           ("🟡 Pendiente de firma del empleado",               "warning"),
    "FIRMADO_EMPLEADO": ("🟠 Firmado por empleado — falta firma de empresa", "warning"),
    "FIRMADO_EMPRESA":  ("🔵 Firmado por empresa — falta certificación",     "info"),
    "CERTIFICADO":      ("✅ Certificado por notario",                        "success"),
}

ALGO_ICONS = {"Ed25519": "🔑", "RSA": "🗝️"}


def _contracts():
    return sorted([p.name for p in DATA_DIR.iterdir() if p.is_dir()]) if DATA_DIR.exists() else []


def _pdf_path(contract_id: str) -> pathlib.Path:
    return DATA_DIR / contract_id / "contrato.pdf"


def _bundle_path(contract_id: str) -> pathlib.Path:
    return DATA_DIR / contract_id / "bundle.json"


def _mostrar_estado(estado: str):
    etiqueta, tipo = ESTADO_INFO.get(estado, (f"🔘 {estado}", "info"))
    getattr(st, tipo)(f"**Estado del contrato:** {etiqueta}")


def render():
    if st.session_state.role != "AUDITOR":
        st.error("Acceso restringido")
        st.stop()

    st.subheader("🔎 Vista Auditor")
    st.caption("Modo solo lectura — puede inspeccionar contratos pero no modificarlos.")

    tab_contratos, tab_log = st.tabs(["📄 Contratos", "📋 Log de auditoría"])

    # ══════════════════════════════════════════════════════════
    # TAB 1 — INSPECCIÓN DE CONTRATOS
    # ══════════════════════════════════════════════════════════
    with tab_contratos:
        contracts = _contracts()
        if not contracts:
            st.info("No hay contratos en el sistema.")
            return

        contract_id = st.selectbox("Seleccionar contrato", contracts)

        pdf_path    = _pdf_path(contract_id)
        bundle_path = _bundle_path(contract_id)

        if not bundle_path.exists():
            st.error("No se encontró el bundle del contrato.")
            return

        bundle = load_bundle(bundle_path)
        estado = get_state(bundle)

        _mostrar_estado(estado)
        st.divider()

        # ── Verificaciones de integridad ───────────────────────
        st.markdown("### 🔍 Integridad")

        ok_pdf   = verify_file_hash(pdf_path, bundle["pdf_sha256"]) if pdf_path.exists() else False
        ok_chain = verify_signature_chain(bundle)

        col1, col2 = st.columns(2)
        with col1:
            st.success("PDF íntegro ✅") if ok_pdf else st.error("PDF alterado ❌")
        with col2:
            st.success("Cadena de firmas válida ✅") if ok_chain else st.error("Cadena rota ❌")

        st.markdown(f"**SHA-256 del documento:** `{bundle.get('pdf_sha256', 'N/A')}`")
        st.divider()

        # ── Firmas ────────────────────────────────────────────
        st.markdown("### ✍️ Firmas registradas")

        sigs = bundle.get("signatures", [])
        if not sigs:
            st.info("No hay firmas registradas en este contrato.")
        else:
            data_to_verify = bundle.get("pdf_sha256", "").encode("utf-8")

            for i, sig in enumerate(sigs):
                role      = sig.get("role", "N/A")
                algo      = sig.get("algorithm", "N/A")
                timestamp = sig.get("timestamp", "N/A")
                icono     = ALGO_ICONS.get(algo, "🔐")

                with st.expander(f"{icono} Firma #{i+1} — {role} ({algo}) — {timestamp}"):
                    try:
                        if algo == "RSA":
                            from core.rsa_signatures import verify_rsa, load_public_key_pem as load_rsa_pub
                            pub = load_rsa_pub(sig["public_key"])
                            ok  = verify_rsa(pub, data_to_verify, sig["signature"])
                        else:  # Ed25519
                            pub = load_public_key_pem(sig["public_key"])
                            ok  = verify_signature(pub, data_to_verify, sig["signature"])

                        if ok:
                            st.success("Firma criptográficamente válida ✅")
                        else:
                            st.error("Firma inválida ❌")
                    except Exception as e:
                        st.error(f"Error al verificar: {e}")

                    st.markdown(f"**Algoritmo:** {algo}")
                    st.markdown(f"**Timestamp:** {timestamp}")

                    prev_hash = sig.get("prev_signature_hash")
                    st.markdown(
                        f"**Hash firma anterior:** `{prev_hash}`"
                        if prev_hash else "**Primera firma** (sin encadenamiento previo)"
                    )

        st.divider()

        # ── Bundle completo (solo auditor puede verlo) ─────────
        st.markdown("### 📦 Bundle completo")
        st.caption("Información interna del contrato — acceso exclusivo del auditor.")
        with st.expander("Ver bundle.json"):
            st.json(bundle)

    # ══════════════════════════════════════════════════════════
    # TAB 2 — LOG DE AUDITORÍA
    # ══════════════════════════════════════════════════════════
    with tab_log:
        st.markdown("### 📋 Registro de eventos del sistema")

        if not AUDIT_LOG.exists():
            st.info("No hay eventos registrados todavía.")
            return

        lineas = AUDIT_LOG.read_text(encoding="utf-8").strip().splitlines()

        if not lineas:
            st.info("El log está vacío.")
            return

        # Mostrar en orden inverso (más reciente primero)
        st.caption(f"{len(lineas)} eventos registrados")

        filtro = st.text_input("🔍 Filtrar eventos", placeholder="usuario, contrato, acción...")

        lineas_filtradas = [
            l for l in reversed(lineas)
            if filtro.lower() in l.lower()
        ] if filtro else list(reversed(lineas))

        for linea in lineas_filtradas:
            st.text(linea)

        st.divider()
        st.download_button(
            label="⬇️ Descargar log completo",
            data=AUDIT_LOG.read_bytes(),
            file_name="audit.log",
            mime="text/plain",
            use_container_width=True,
        )