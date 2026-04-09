# src/views/admin.py

import hashlib
import pathlib

import streamlit as st
from streamlit_drawable_canvas import st_canvas

from database.db import get_connection
from database.user_repository import save_signature_hash, save_face_template
from core.signature_verifier import compute_signature_hash, save_reference_image
from core.face_verifier import (
    process_captured_image,
    compute_face_hash,
    save_face_reference,
    save_face_encoding,
    FACE_THRESHOLD,
)

ROLES_DISPONIBLES = ["EMPLEADO", "EMPRESA", "AUDITOR", "NOTARIO"]
ICONOS_ROL        = {
    "EMPLEADO": "👨‍💼",
    "EMPRESA":  "🏢",
    "AUDITOR":  "🔎",
    "NOTARIO":  "⚖️",
}

BASE_DIR     = pathlib.Path(__file__).resolve().parents[1].parent
SIGN_REF_DIR = BASE_DIR / "keys" / "signatures"
FACE_REF_DIR = BASE_DIR / "keys" / "faces"


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def _get_all_users():
    conn = get_connection()
    users = conn.execute(
        "SELECT id, username, role, signature_hash, face_template FROM users "
        "WHERE role != 'ADMIN' ORDER BY role, username"
    ).fetchall()
    conn.close()
    return [dict(u) for u in users]


def _insert_user(username: str, password: str, role: str) -> tuple[bool, str]:
    if not username.strip() or not password.strip():
        return False, "El usuario y la contraseña no pueden estar vacíos."
    if len(password) < 6:
        return False, "La contraseña debe tener al menos 6 caracteres."
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username.strip(), _hash_password(password), role)
        )
        conn.commit()
        return True, username.strip()
    except Exception as e:
        if "UNIQUE constraint" in str(e):
            return False, f"El usuario **{username}** ya existe."
        return False, f"Error inesperado: {e}"
    finally:
        conn.close()


def _update_user(user_id: int, new_username: str, new_role: str, new_password: str = "") -> tuple[bool, str]:
    if not new_username.strip():
        return False, "El nombre de usuario no puede estar vacío."
    conn = get_connection()
    try:
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ? AND id != ?",
            (new_username.strip(), user_id)
        ).fetchone()
        if existing:
            return False, f"El nombre **{new_username}** ya está en uso."
        if new_password:
            if len(new_password) < 6:
                return False, "La nueva contraseña debe tener al menos 6 caracteres."
            conn.execute(
                "UPDATE users SET username=?, role=?, password_hash=? WHERE id=? AND role!='ADMIN'",
                (new_username.strip(), new_role, _hash_password(new_password), user_id)
            )
        else:
            conn.execute(
                "UPDATE users SET username=?, role=? WHERE id=? AND role!='ADMIN'",
                (new_username.strip(), new_role, user_id)
            )
        conn.commit()
        return True, "Usuario actualizado correctamente ✅"
    except Exception as e:
        return False, f"Error al actualizar: {e}"
    finally:
        conn.close()


def _delete_user(user_id: int, username: str) -> tuple[bool, str]:
    conn = get_connection()
    try:
        conn.execute("DELETE FROM users WHERE id=? AND role!='ADMIN'", (user_id,))
        conn.commit()
        for path in [
            SIGN_REF_DIR / f"{username}_referencia.png",
            FACE_REF_DIR / f"{username}_rostro.png",
            FACE_REF_DIR / f"{username}_encoding.bin",
        ]:
            if path.exists():
                path.unlink()
        return True, f"Usuario **{username}** eliminado ✅"
    except Exception as e:
        return False, f"Error al eliminar: {e}"
    finally:
        conn.close()


def _sign_ref_path(username: str) -> pathlib.Path:
    return SIGN_REF_DIR / f"{username}_referencia.png"


def _face_ref_path(username: str) -> pathlib.Path:
    return FACE_REF_DIR / f"{username}_rostro.png"


def _face_enc_path(username: str) -> pathlib.Path:
    return FACE_REF_DIR / f"{username}_encoding.bin"


# ──────────────────────────────────────────────────────────────
# FORMULARIO DE EDICIÓN INLINE
# ──────────────────────────────────────────────────────────────
def _render_edit_form(user: dict):
    uid      = user["id"]
    username = user["username"]

    st.markdown(f"**Editando:** `{username}`")

    # ── Datos básicos ──────────────────────────────────────────
    with st.form(key=f"form_edit_{uid}"):
        col1, col2 = st.columns(2)
        with col1:
            new_username = st.text_input("Nombre de usuario", value=username)
            new_role = st.selectbox(
                "Rol", ROLES_DISPONIBLES,
                index=ROLES_DISPONIBLES.index(user["role"])
                      if user["role"] in ROLES_DISPONIBLES else 0,
            )
        with col2:
            new_password = st.text_input("Nueva contraseña (vacío = no cambiar)", type="password")
            confirm_password = st.text_input("Confirmar nueva contraseña", type="password")

        col_g, col_c = st.columns(2)
        with col_g:
            guardar = st.form_submit_button("💾 Guardar datos", use_container_width=True)
        with col_c:
            cancelar = st.form_submit_button("✖ Cancelar", use_container_width=True)

    if guardar:
        if new_password and new_password != confirm_password:
            st.error("Las contraseñas no coinciden ❌")
        else:
            ok, msg = _update_user(uid, new_username, new_role, new_password)
            if ok:
                st.success(msg)
                st.session_state[f"editing_{uid}"] = False
                st.rerun()
            else:
                st.error(msg)

    if cancelar:
        st.session_state[f"editing_{uid}"] = False
        st.rerun()

    # ── Firma de referencia (EMPLEADO) ─────────────────────────
    if user["role"] in ("EMPLEADO", "EMPRESA"):
        st.markdown("##### ✍️ Firma de referencia")
        ref_path        = _sign_ref_path(username)
        update_firma_key = f"update_firma_{uid}"

        if ref_path.exists():
            col_estado, col_reemplazar = st.columns([3, 1])
            with col_estado:
                st.success("Firma de referencia registrada 🔒")
            with col_reemplazar:
                if not st.session_state.get(update_firma_key, False):
                    if st.button("🔄 Reemplazar", key=f"btn_replace_firma_{uid}", use_container_width=True):
                        st.session_state[update_firma_key] = True
                        st.rerun()
        else:
            st.warning("Sin firma de referencia registrada.")
            if not st.session_state.get(update_firma_key, False):
                if st.button("➕ Agregar firma", key=f"btn_add_firma_{uid}", use_container_width=True):
                    st.session_state[update_firma_key] = True
                    st.rerun()

        if st.session_state.get(update_firma_key, False):
            st.caption("Dibuje la nueva firma de referencia.")
            canvas_edit = st_canvas(
                fill_color="rgba(255,255,255,0)", stroke_width=3,
                stroke_color="#000000", background_color="#ffffff",
                height=200, width=500, drawing_mode="freedraw",
                key=f"canvas_edit_firma_{uid}",
            )
            col_gf, col_cf = st.columns(2)
            with col_gf:
                if st.button("💾 Guardar firma", key=f"save_firma_{uid}", use_container_width=True):
                    img_data = canvas_edit.image_data
                    if img_data is None or int(img_data.sum()) == 0:
                        st.error("Debe dibujar la firma antes de guardar.")
                    else:
                        save_reference_image(img_data, ref_path)
                        save_signature_hash(username, compute_signature_hash(img_data))
                        st.session_state[update_firma_key] = False
                        st.success("Firma actualizada ✅")
                        st.rerun()
            with col_cf:
                if st.button("✖ Cancelar", key=f"cancel_firma_{uid}", use_container_width=True):
                    st.session_state[update_firma_key] = False
                    st.rerun()

    # ── Rostro de referencia (NOTARIO) ─────────────────────────
    if user["role"] == "NOTARIO":
        st.markdown("##### 📷 Rostro de referencia")
        face_path        = _face_ref_path(username)
        update_face_key  = f"update_face_{uid}"

        if _face_enc_path(username).exists():
            col_estado, col_reemplazar = st.columns([3, 1])
            with col_estado:
                st.success("Rostro de referencia registrado 🔒")
            with col_reemplazar:
                if not st.session_state.get(update_face_key, False):
                    if st.button("🔄 Reemplazar", key=f"btn_replace_face_{uid}", use_container_width=True):
                        st.session_state[update_face_key] = True
                        st.rerun()
        else:
            st.warning("Sin rostro de referencia registrado.")
            if not st.session_state.get(update_face_key, False):
                if st.button("📷 Capturar rostro", key=f"btn_add_face_{uid}", use_container_width=True):
                    st.session_state[update_face_key] = True
                    st.rerun()

        if st.session_state.get(update_face_key, False):
            st.caption("Haga clic en 'Capturar' para abrir la cámara y registrar el rostro.")
            col_cap, col_can = st.columns(2)
            st.info("📷 Centre su rostro en la cámara y presione el botón de captura.")
            foto = st.camera_input("Capturar nuevo rostro", key=f"admin_face_edit_{uid}")

            if foto:
                try:
                    encoding, face_png = process_captured_image(foto)
                    save_face_reference(face_png, face_path)
                    save_face_encoding(encoding, _face_enc_path(username))
                    save_face_template(username, compute_face_hash(encoding))
                    st.session_state[update_face_key] = False
                    st.success("Rostro de referencia actualizado ✅")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error al procesar captura: {e}")

            if st.button("✖ Cancelar", key=f"cancel_face_{uid}", use_container_width=True):
                st.session_state[update_face_key] = False
                st.rerun()


# ──────────────────────────────────────────────────────────────
# RENDER PRINCIPAL
# ──────────────────────────────────────────────────────────────
def render():
    if st.session_state.role != "ADMIN":
        st.error("Acceso restringido.")
        st.stop()

    SIGN_REF_DIR.mkdir(parents=True, exist_ok=True)
    FACE_REF_DIR.mkdir(parents=True, exist_ok=True)

    st.subheader("⚙️ Panel de Administración")

    tab_crear, tab_usuarios = st.tabs(["➕ Crear usuario", "👥 Usuarios registrados"])

    # ──────────────────────────────────────────
    # TAB 1: CREAR USUARIO
    # ──────────────────────────────────────────
    with tab_crear:
        st.markdown("### Registrar nuevo usuario")

        pending = st.session_state.get("admin_new_user")

        # ── PASO 1: datos básicos ──────────────
        if not pending:
            with st.form("form_crear_usuario", clear_on_submit=False):
                col1, col2 = st.columns(2)
                with col1:
                    nuevo_username = st.text_input("Nombre de usuario")
                    nuevo_password = st.text_input("Contraseña", type="password")
                with col2:
                    confirmar_password = st.text_input("Confirmar contraseña", type="password")
                    nuevo_rol = st.selectbox("Rol", ROLES_DISPONIBLES)

                lbl = (
                    "Siguiente → Capturar firma de referencia" if nuevo_rol in ("EMPLEADO", "EMPRESA")
                    else "Siguiente → Capturar rostro de referencia" if nuevo_rol == "NOTARIO"
                    else "Registrar usuario"
                )
                paso1_ok = st.form_submit_button(lbl, use_container_width=True)

            if paso1_ok:
                errores = []
                if not nuevo_username.strip():
                    errores.append("El nombre de usuario no puede estar vacío.")
                if len(nuevo_password) < 6:
                    errores.append("La contraseña debe tener al menos 6 caracteres.")
                if nuevo_password != confirmar_password:
                    errores.append("Las contraseñas no coinciden.")
                if errores:
                    for e in errores:
                        st.error(e)
                else:
                    st.session_state["admin_new_user"] = {
                        "username": nuevo_username.strip(),
                        "password": nuevo_password,
                        "role":     nuevo_rol,
                    }
                    st.rerun()

        # ── PASO 2: captura según rol ──────────
        else:
            rol_pending = pending["role"]

            # EMPLEADO o EMPRESA → firma visual
            if rol_pending in ("EMPLEADO", "EMPRESA"):
                st.info(
                    f"**Paso 2 de 2** — Dibuje la firma de referencia para "
                    f"`{pending['username']}`. Se requiere al menos **65% de similitud** al firmar."
                )
                canvas_ref = st_canvas(
                    fill_color="rgba(255,255,255,0)", stroke_width=3,
                    stroke_color="#000000", background_color="#ffffff",
                    height=200, width=500, drawing_mode="freedraw",
                    key=f"admin_canvas_firma_ref_{rol_pending}",
                )
                col_reg, col_can = st.columns(2)
                with col_reg:
                    if st.button("✅ Registrar con esta firma", use_container_width=True):
                        img_data = canvas_ref.image_data
                        if img_data is None or int(img_data.sum()) == 0:
                            st.error("Debe dibujar la firma antes de registrar.")
                        else:
                            ok, result = _insert_user(pending["username"], pending["password"], pending["role"])
                            if not ok:
                                st.error(result)
                            else:
                                ref_path = _sign_ref_path(result)
                                save_reference_image(img_data, ref_path)
                                save_signature_hash(result, compute_signature_hash(img_data))
                                st.session_state.pop("admin_new_user", None)
                                st.success(f"Usuario **{result}** registrado con firma ✅")
                                st.rerun()
                with col_can:
                    if st.button("✖ Cancelar", use_container_width=True):
                        st.session_state.pop("admin_new_user", None)
                        st.rerun()

            # NOTARIO → reconocimiento facial
            elif rol_pending == "NOTARIO":
                st.info(
                    f"**Paso 2 de 2** — Capture el rostro de referencia para "
                    f"`{pending['username']}`. El notario deberá superar un **{int(FACE_THRESHOLD*100)}% "
                    f"de similitud** al autenticarse."
                )
                st.caption("Asegúrese de tener buena iluminación y estar frente a la cámara.")

                st.info("📷 Centre su rostro en la cámara y presione el botón de captura.")
                foto = st.camera_input("Capturar rostro de referencia", key="admin_face_registro")

                if foto:
                    try:
                        encoding, face_png = process_captured_image(foto)
                        ok, result = _insert_user(pending["username"], pending["password"], pending["role"])
                        if not ok:
                            st.error(result)
                        else:
                            save_face_reference(face_png, _face_ref_path(result))
                            save_face_encoding(encoding, _face_enc_path(result))
                            save_face_template(result, compute_face_hash(encoding))
                            st.session_state.pop("admin_new_user", None)
                            st.success(f"Usuario **{result}** registrado con rostro de referencia ✅")
                            st.rerun()
                    except Exception as e:
                        st.error(f"Error al procesar captura: {e}")

                if st.button("✖ Cancelar registro", use_container_width=True):
                    st.session_state.pop("admin_new_user", None)
                    st.rerun()

            # EMPRESA / AUDITOR → sin biometría
            else:
                st.info(
                    f"**Confirmar registro** — `{pending['username']}` "
                    f"como **{rol_pending}** (sin biometría requerida)."
                )
                col_reg, col_can = st.columns(2)
                with col_reg:
                    if st.button("✅ Registrar usuario", use_container_width=True):
                        ok, result = _insert_user(pending["username"], pending["password"], pending["role"])
                        if ok:
                            st.session_state.pop("admin_new_user", None)
                            st.success(f"Usuario **{result}** registrado ✅")
                            st.rerun()
                        else:
                            st.error(result)
                with col_can:
                    if st.button("✖ Cancelar", use_container_width=True, key="cancel_no_bio"):
                        st.session_state.pop("admin_new_user", None)
                        st.rerun()

    # ──────────────────────────────────────────
    # TAB 2: VER, EDITAR Y ELIMINAR USUARIOS
    # ──────────────────────────────────────────
    with tab_usuarios:
        st.markdown("### Usuarios registrados")

        users = _get_all_users()
        if not users:
            st.info("No hay usuarios registrados todavía.")
            return

        roles_encontrados = sorted(set(u["role"] for u in users))

        for rol in roles_encontrados:
            usuarios_del_rol = [u for u in users if u["role"] == rol]
            icono = ICONOS_ROL.get(rol, "👤")
            st.markdown(f"#### {icono} {rol} ({len(usuarios_del_rol)})")

            for user in usuarios_del_rol:
                uid         = user["id"]
                editing_key = f"editing_{uid}"
                confirm_key = f"confirm_delete_{uid}"

                if not st.session_state.get(editing_key, False):
                    col_nombre, col_bio, col_editar, col_eliminar = st.columns([3, 1, 1, 1])

                    with col_nombre:
                        st.write(f"🔹 `{user['username']}`")

                    with col_bio:
                        if user["role"] in ("EMPLEADO", "EMPRESA"):
                            tiene = _sign_ref_path(user["username"]).exists()
                            st.write("✍️ ✅" if tiene else "✍️ ❌")
                        elif user["role"] == "NOTARIO":
                            tiene = _face_enc_path(user["username"]).exists()
                            st.write("📷 ✅" if tiene else "📷 ❌")

                    with col_editar:
                        if st.button("✏️ Editar", key=f"edit_{uid}"):
                            for u in users:
                                if u["id"] != uid:
                                    st.session_state[f"editing_{u['id']}"] = False
                            st.session_state[editing_key] = True
                            st.session_state[confirm_key] = False
                            st.rerun()

                    with col_eliminar:
                        if not st.session_state.get(confirm_key, False):
                            if st.button("🗑️ Eliminar", key=f"del_{uid}"):
                                st.session_state[confirm_key] = True
                                st.rerun()
                        else:
                            st.warning(f"¿Eliminar **{user['username']}**?")
                            col_si, col_no = st.columns(2)
                            with col_si:
                                if st.button("✅ Sí", key=f"confirm_yes_{uid}"):
                                    ok, msg = _delete_user(uid, user["username"])
                                    st.session_state[confirm_key] = False
                                    st.success(msg) if ok else st.error(msg)
                                    st.rerun()
                            with col_no:
                                if st.button("❌ No", key=f"confirm_no_{uid}"):
                                    st.session_state[confirm_key] = False
                                    st.rerun()
                else:
                    _render_edit_form(user)

            st.divider()