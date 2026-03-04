import streamlit as st
from database.user_repository import authenticate


def login():

    username = st.text_input("Usuario")
    password = st.text_input("Contraseña", type="password")

    if st.button("Ingresar"):

        user = authenticate(username, password)

        if user:
            st.session_state.user = user["username"]
            st.session_state.role = user["role"]
            st.success("Login correcto")
            st.rerun()

        else:
            st.error("Credenciales incorrectas")