# src/app.py
import streamlit as st

from database.db import init_db
from database.user_repository import authenticate  # <-- debe existir
from views.empleado import render as empleado_render
from views.empresa import render as empresa_render
from views.auditor import render as auditor_render
from views.verificador import render as verificador_render

APP_TITLE = "Sistema de Firma Multillave (Demo)"


def init_session():
    st.session_state.setdefault("user", None)   # username
    st.session_state.setdefault("role", None)   # EMPLEADO | EMPRESA | AUDITOR


def do_logout():
    st.session_state.user = None
    st.session_state.role = None
    st.rerun()


def login_screen():
    st.title(APP_TITLE)
    st.subheader("🔐 Iniciar sesión")

    with st.form("login_form"):
        username = st.text_input("Usuario")
        password = st.text_input("Contraseña", type="password")
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
    st.title(APP_TITLE)

    st.sidebar.header("Menú")
    st.sidebar.write(f"👤 Usuario: **{st.session_state.user}**")
    st.sidebar.write(f"🔑 Rol: **{st.session_state.role}**")

    if st.sidebar.button("Cerrar sesión"):
        do_logout()

    option = st.sidebar.radio(
        "Seleccione una opción:",
        ["Empleado / Proveedor", "Empresa", "Auditor / Notario", "Verificador"]
    )

    # Si es público, solo dejar ver verificador
    if st.session_state.role == "PUBLIC" and option != "Verificador":
        st.warning("Modo público: solo puedes usar el Verificador.")
        verificador_render()
        return

    if option == "Empleado / Proveedor":
        empleado_render()
    elif option == "Empresa":
        empresa_render()
    elif option == "Auditor / Notario":
        auditor_render()
    else:
        verificador_render()


def main():
    st.set_page_config(page_title=APP_TITLE, layout="wide")
    init_db()
    init_session()

    # Si no hay sesión -> login
    if not st.session_state.user:
        login_screen()
        return

    # Si hay sesión -> app
    main_app()


if __name__ == "__main__":
   main()