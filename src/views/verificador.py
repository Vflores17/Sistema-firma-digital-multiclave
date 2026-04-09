# src/views/verificador.py

import json
import pathlib

import streamlit as st

from core.hashing import sha256_bytes
from core.bundle import verify_signature_chain
from core.signatures import load_public_key_pem, verify_signature
from core.hybrid_encryption import decrypt_certified_package, PKG_EXT

BASE_DIR = pathlib.Path(__file__).resolve().parents[1].parent
TEMP_DIR = BASE_DIR / "data" / "_temp"

ALGO_ICONS = {"Ed25519": "🔑", "RSA": "🗝️"}
ROL_ICONS  = {"EMPLEADO": "👨‍💼", "EMPRESA": "🏢", "AUDITOR": "⚖️"}


def _verificar_bundle(bundle: dict, pdf_bytes: bytes):
    """Muestra los resultados de verificación del bundle y PDF."""

    st.markdown("### 🔍 Integridad del documento")
    pdf_hash    = sha256_bytes(pdf_bytes)
    hash_bundle = bundle.get("pdf_sha256", "")
    ok_pdf      = pdf_hash == hash_bundle

    col1, col2 = st.columns(2)
    with col1:
        st.success("PDF íntegro ✅") if ok_pdf else st.error("PDF alterado ❌")
    with col2:
        ok_chain = verify_signature_chain(bundle)
        st.success("Cadena de firmas válida ✅") if ok_chain else st.error("Cadena de firmas rota ❌")

    st.markdown(f"**SHA-256 del documento:** `{pdf_hash}`")
    st.divider()

    st.markdown("### ✍️ Firmas registradas")
    sigs = bundle.get("signatures", [])
    if not sigs:
        st.info("No hay firmas en este bundle.")
        return

    data_to_verify = hash_bundle.encode("utf-8")

    for i, sig in enumerate(sigs):
        role  = sig.get("role", "N/A")
        algo  = sig.get("algorithm", "N/A")
        ts    = sig.get("timestamp", "N/A")
        icono = ROL_ICONS.get(role, "🔐")

        with st.expander(f"{icono} Firma #{i+1} — {role} ({algo}) — {ts}"):
            try:
                pub = load_public_key_pem(sig["public_key"])
                ok  = verify_signature(pub, data_to_verify, sig["signature"])
                st.success("Firma válida ✅") if ok else st.error("Firma inválida ❌")
            except Exception as e:
                st.error(f"Error al verificar: {e}")
            st.markdown(f"**Algoritmo:** {algo}")
            prev = sig.get("prev_signature_hash")
            st.markdown(
                f"**Hash firma anterior:** `{prev}`"
                if prev else "**Primera firma** (sin encadenamiento previo)"
            )

    st.divider()
    st.markdown("### 📦 Información del contrato")
    st.markdown(f"**ID:** `{bundle.get('contract_id', 'N/A')}`")
    st.markdown(f"**Estado:** `{bundle.get('state', 'N/A')}`")
    st.markdown(f"**Creado:** `{bundle.get('created_at', 'N/A')}`")


def render():
    TEMP_DIR.mkdir(parents=True, exist_ok=True)

    st.subheader("✅ Verificador Público")

    tab_pkg, tab_manual = st.tabs([
        f"📦 Paquete certificado ({PKG_EXT})",
        "📄 Verificación manual (PDF + bundle)"
    ])

    # ══════════════════════════════════════════════════════════
    # TAB 1 — PAQUETE CERTIFICADO (descifrado + verificación)
    # ══════════════════════════════════════════════════════════
    with tab_pkg:
        st.markdown("### 🔐 Descifrar y verificar paquete certificado")
        st.caption(
            f"Suba el archivo `{PKG_EXT}` generado por el notario y la clave privada RSA "
            "para descifrar y verificar el contrato completo."
        )

        col1, col2 = st.columns(2)
        with col1:
            uploaded_pkg = st.file_uploader(
                f"Paquete certificado (*{PKG_EXT})",
                type=[PKG_EXT.lstrip(".")],
                key="v_pkg"
            )
        with col2:
            uploaded_pem = st.file_uploader(
                "Clave privada del notario (.pem)",
                type=["pem"],
                key="v_pem"
            )

        if not uploaded_pkg or not uploaded_pem:
            st.info("Suba ambos archivos para descifrar y verificar.")
            return

        if st.button("🔓 Descifrar y verificar", use_container_width=True, type="primary"):
            try:
                # Guardar temporalmente
                pkg_path = TEMP_DIR / "uploaded.certified"
                pkg_path.write_bytes(uploaded_pkg.getvalue())

                private_key_pem = uploaded_pem.getvalue().decode("utf-8")

                with st.spinner("Descifrando paquete..."):
                    pdf_bytes, bundle, meta = decrypt_certified_package(
                        pkg_path, private_key_pem
                    )

                st.success("✅ Paquete descifrado correctamente")

                # Metadatos del paquete
                st.markdown("### 📋 Información del paquete")
                col_m1, col_m2 = st.columns(2)
                with col_m1:
                    st.markdown(f"**Contrato:** `{meta.get('contract_id', 'N/A')}`")
                    st.markdown(f"**Notario:** `{meta.get('notario', 'N/A')}`")
                with col_m2:
                    st.markdown(f"**Fecha:** `{meta.get('fecha', 'N/A')}`")
                    st.markdown(f"**Algoritmos:** `{meta.get('algoritmos', 'N/A')}`")

                st.divider()

                # Verificación completa
                _verificar_bundle(bundle, pdf_bytes)

                st.divider()

                # Descarga del PDF
                st.markdown("### 📥 Descargar documento")
                st.download_button(
                    label="⬇️ Descargar PDF del contrato",
                    data=pdf_bytes,
                    file_name=f"{meta.get('contract_id', 'contrato')}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                )

            except ValueError as e:
                st.error(f"❌ {e}")
            except Exception as e:
                st.error(f"Error inesperado: {e}")

    # ══════════════════════════════════════════════════════════
    # TAB 2 — VERIFICACIÓN MANUAL (PDF + bundle por separado)
    # ══════════════════════════════════════════════════════════
    with tab_manual:
        st.markdown("### 📄 Verificación manual")
        st.caption("Suba el PDF y el bundle.json por separado para verificar.")

        col1, col2 = st.columns(2)
        with col1:
            uploaded_pdf    = st.file_uploader("Contrato PDF", type=["pdf"], key="v_pdf")
        with col2:
            uploaded_bundle = st.file_uploader("bundle.json",  type=["json"], key="v_bundle")

        if not uploaded_pdf or not uploaded_bundle:
            st.info("Suba ambos archivos para verificar.")
            return

        try:
            bundle    = json.loads(uploaded_bundle.getvalue().decode("utf-8"))
            pdf_bytes = uploaded_pdf.getvalue()
            _verificar_bundle(bundle, pdf_bytes)
        except Exception as e:
            st.error(f"Error al procesar los archivos: {e}")