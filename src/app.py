# src/app.py
import streamlit as st

from database.db import init_db
from database.user_repository import authenticate
from views.empleado import render as empleado_render
from views.empresa import render as empresa_render
from views.auditor import render as auditor_render
from views.notario import render as notario_render
from views.verificador import render as verificador_render
from views.admin import render as admin_render

APP_TITLE = "Sistema de Firma Multillave (Demo)"

ROLE_VIEW_MAP = {
    "EMPLEADO": [("👨‍💼 Mi Panel", empleado_render)],
    "EMPRESA":  [("🏢 Mi Panel",  empresa_render)],
    "AUDITOR":  [("🔎 Mi Panel",  auditor_render)],
    "NOTARIO":  [("⚖️ Mi Panel",  notario_render)],
    "ADMIN": [
        ("⚙️ Administración", admin_render),
        ("👨‍💼 Vista Empleado", empleado_render),
        ("🏢 Vista Empresa",   empresa_render),
        ("🔎 Vista Auditor",   auditor_render),
        ("⚖️ Vista Notario",   notario_render),
        ("✅ Verificador",     verificador_render),
    ],
    "PUBLIC": [("✅ Verificador", verificador_render)],
}


def init_session():
    st.session_state.setdefault("user", None)
    st.session_state.setdefault("role", None)


def do_logout():
    st.session_state.user = None
    st.session_state.role = None
    st.rerun()


def login_screen():
    st.title(APP_TITLE)
    st.subheader("🔐 Iniciar sesión")
    with st.form("login_form"):
        username  = st.text_input("Usuario")
        password  = st.text_input("Contraseña", type="password")
        submitted = st.form_submit_button("Ingresar")
    if submitted:
        user = authenticate(username, password)
        if user:
            st.session_state.user = user["username"]
            st.session_state.role = user["role"]
            st.success("Login correcto ✅")
            st.rerun()
        else:
            st.error("Usuario o contraseña incorrectos ❌")
    st.divider()
    st.subheader("✅ Verificador público")
    st.caption("Esta opción no requiere login.")
    if st.button("Ir a Verificador"):
        st.session_state.user = "PUBLIC"
        st.session_state.role = "PUBLIC"
        st.rerun()


def main_app():
    role = st.session_state.role
    user = st.session_state.user
    allowed_views = ROLE_VIEW_MAP.get(role, [])
    if not allowed_views:
        st.error("Rol no reconocido. Cerrando sesión.")
        do_logout()
        return
    st.sidebar.title("Menú")
    st.sidebar.write(f"👤 **{user}**")
    st.sidebar.write(f"🔑 Rol: **{role}**")
    st.sidebar.divider()
    labels = [label for label, _ in allowed_views]
    if len(labels) == 1:
        selected_label = labels[0]
        st.sidebar.markdown(f"**{selected_label}**")
    else:
        selected_label = st.sidebar.radio("Seleccione una opción:", labels)
    st.sidebar.divider()
    if st.sidebar.button("Cerrar sesión"):
        do_logout()
    st.title(APP_TITLE)
    render_fn = next(fn for lbl, fn in allowed_views if lbl == selected_label)
    render_fn()


def main():
    st.set_page_config(page_title=APP_TITLE, layout="wide")
    init_db()
    init_session()
    if not st.session_state.user:
        login_screen()
        return
    main_app()


if __name__ == "__main__":
    main()