# src/views/verificador.py
import json
import pathlib
import streamlit as st

from core.hashing import sha256_bytes
from core.bundle import verify_signature_chain
from core.signatures import load_public_key_pem, verify_signature
from core.encryption import decrypt_file, read_key_file, EncryptedFileError

BASE_DIR = pathlib.Path(__file__).resolve().parents[1].parent
TEMP_DIR = BASE_DIR / "data" / "_temp"


def render():
    st.subheader("✅ Vista Verificador (Público)")
    st.caption("Sube PDF + bundle.json. Si tienes .enc, sube también la clave .key para descifrar.")

    TEMP_DIR.mkdir(parents=True, exist_ok=True)

    col1, col2 = st.columns(2)

    with col1:
        uploaded_pdf = st.file_uploader("Subir contrato.pdf (opcional)", type=["pdf"], key="v_pdf")
        uploaded_enc = st.file_uploader("Subir contrato.pdf.enc (opcional)", type=["enc"], key="v_enc")
        uploaded_key = st.file_uploader("Clave .key (solo si subes .enc)", type=["key"], key="v_key")

    with col2:
        uploaded_bundle = st.file_uploader("Subir bundle.json", type=["json"], key="v_bundle")

    if not uploaded_bundle:
        st.info("Sube el bundle.json para verificar.")
        return

    bundle = json.loads(uploaded_bundle.getvalue().decode("utf-8"))
    pdf_bytes = b""

    if uploaded_pdf:
        pdf_bytes = uploaded_pdf.getvalue()

    if uploaded_enc and uploaded_key:
        try:
            enc_path = TEMP_DIR / "uploaded.enc"
            key_path = TEMP_DIR / "uploaded.key"
            enc_path.write_bytes(uploaded_enc.getvalue())
            key_path.write_bytes(uploaded_key.getvalue())

            aes_key = read_key_file(key_path)
            restored = decrypt_file(enc_path, aes_key, output_dir=TEMP_DIR, force_filename="restored.pdf")
            pdf_bytes = restored.read_bytes()
            st.success("Descifrado ✅ (usando la clave .key)")
        except EncryptedFileError as e:
            st.error(f"No se pudo descifrar: {e}")
            return
        except Exception as e:
            st.error(f"Error inesperado: {e}")
            return

    # Integridad
    if pdf_bytes:
        pdf_hash = sha256_bytes(pdf_bytes)
        st.write("SHA-256 calculado:", pdf_hash)
        st.write("SHA-256 en bundle:", bundle.get("pdf_sha256", "N/A"))
        st.write("Integridad:", "✅" if pdf_hash == bundle.get("pdf_sha256") else "❌")
    else:
        st.warning("No se subió PDF (o no se pudo restaurar). Se verificará cadena y firmas contra el hash del bundle.")

    # Cadena
    ok_chain = verify_signature_chain(bundle)
    st.write("Cadena de firmas:", "✅" if ok_chain else "❌")

    # Firmas
    st.markdown("### Firmas")
    sigs = bundle.get("signatures", [])
    if not sigs:
        st.info("No hay firmas en el bundle.")
        return

    data_to_verify = bundle.get("pdf_sha256", "").encode("utf-8")

    for sig in sigs:
        role = sig.get("role", "N/A")
        try:
            pub = load_public_key_pem(sig["public_key"])
            ok = verify_signature(pub, data_to_verify, sig["signature"])
            st.write(f"{role}: {'✅' if ok else '❌'}")
        except Exception:
            st.write(f"{role}: ❌ (error al cargar/verificar)")

    st.markdown("### Bundle completo")
    st.json(bundle)