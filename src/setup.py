#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
setup.py

Valida e instala todas las dependencias del proyecto antes de
levantar el servidor Streamlit.

Uso:
    python setup.py
"""

import sys
import subprocess
import importlib

# ── Versión mínima de Python ───────────────────────────────────
PYTHON_MIN = (3, 10)

# ── Dependencias: (nombre_import, nombre_pip, version_pip) ────
DEPENDENCIAS = [
    ("streamlit",                  "streamlit",                   "1.35.0"),
    ("streamlit_drawable_canvas",  "streamlit-drawable-canvas",   "0.9.3"),
    ("cryptography",               "cryptography",                "42.0.8"),
    ("nacl",                       "PyNaCl",                      "1.5.0"),
    ("PIL",                        "Pillow",                      "10.3.0"),
    ("numpy",                      "numpy",                       "1.26.4"),
    ("skimage",                    "scikit-image",                "0.22.0"),
    ("reportlab",                  "reportlab",                   "4.1.0"),
    ("pypdf",                      "pypdf",                       "4.2.0"),
    ("qrcode",                     "qrcode[pil]",                 "7.4.2"),
    ("face_recognition",           "face-recognition",            "1.3.0"),
]

# face_recognition requiere pasos extra en Windows
FACE_REC_INSTRUCCIONES = """
  face-recognition requiere dlib para funcionar.
  Si la instalacion automatica falla, ejecute manualmente:

      pip install cmake
      pip install dlib
      pip install face-recognition==1.3.0

  En Windows tambien puede necesitar:
      Visual Studio Build Tools (https://visualstudio.microsoft.com/visual-cpp-build-tools/)
"""

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


def print_header():
    print(f"\n{BOLD}{CYAN}{'='*55}")
    print("  Sistema de Firma Digital Multillave")
    print("  Validador de dependencias")
    print(f"{'='*55}{RESET}\n")


def verificar_python():
    version = sys.version_info[:2]
    if version < PYTHON_MIN:
        print(f"{RED}✗ Python {'.'.join(map(str, version))} detectado.")
        print(f"  Se requiere Python {'.'.join(map(str, PYTHON_MIN))} o superior.{RESET}")
        sys.exit(1)
    print(f"{GREEN}✓ Python {'.'.join(map(str, version))} — OK{RESET}")


def esta_instalada(nombre_import: str) -> bool:
    try:
        importlib.import_module(nombre_import)
        return True
    except ImportError:
        return False


def instalar(nombre_pip: str, version: str, es_face_rec: bool = False) -> bool:
    paquete = f"{nombre_pip}=={version}" if "[" not in nombre_pip else f"{nombre_pip}"
    print(f"  {YELLOW}Instalando {paquete}...{RESET}")

    if es_face_rec:
        # Intentar instalar cmake y dlib primero
        for dep in ["cmake", "dlib"]:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", dep, "-q"],
                capture_output=True
            )

    resultado = subprocess.run(
        [sys.executable, "-m", "pip", "install", paquete, "-q"],
        capture_output=True,
        text=True
    )

    if resultado.returncode != 0:
        return False
    return True


def validar_e_instalar():
    faltantes      = []
    instaladas     = []
    fallidas       = []
    face_rec_fallo = False

    print(f"{BOLD}Verificando dependencias...{RESET}\n")

    for nombre_import, nombre_pip, version in DEPENDENCIAS:
        if esta_instalada(nombre_import):
            print(f"  {GREEN}✓{RESET} {nombre_pip}")
            instaladas.append(nombre_pip)
        else:
            print(f"  {YELLOW}✗{RESET} {nombre_pip} — no instalada")
            faltantes.append((nombre_import, nombre_pip, version))

    if not faltantes:
        print(f"\n{GREEN}{BOLD}Todas las dependencias están instaladas.{RESET}")
        return True

    print(f"\n{YELLOW}Instalando {len(faltantes)} dependencia(s) faltante(s)...{RESET}\n")

    for nombre_import, nombre_pip, version in faltantes:
        es_face = nombre_pip == "face-recognition"
        ok = instalar(nombre_pip, version, es_face_rec=es_face)

        if ok and esta_instalada(nombre_import):
            print(f"  {GREEN}✓ {nombre_pip} instalado correctamente{RESET}")
        else:
            print(f"  {RED}✗ No se pudo instalar {nombre_pip}{RESET}")
            fallidas.append(nombre_pip)
            if es_face:
                face_rec_fallo = True

    if fallidas:
        print(f"\n{RED}{BOLD}Las siguientes dependencias no pudieron instalarse:{RESET}")
        for f in fallidas:
            print(f"  {RED}• {f}{RESET}")

        if face_rec_fallo:
            print(f"{YELLOW}{FACE_REC_INSTRUCCIONES}{RESET}")

        print(f"\n{YELLOW}Intente instalarlas manualmente y vuelva a ejecutar setup.py{RESET}\n")
        return False

    print(f"\n{GREEN}{BOLD}Todas las dependencias instaladas correctamente.{RESET}")
    return True


def levantar_streamlit():
    import pathlib
    app_path = pathlib.Path(__file__).parent / "src" / "app.py"

    if not app_path.exists():
        print(f"{RED}No se encontró src/app.py en {app_path}{RESET}")
        sys.exit(1)

    print(f"\n{CYAN}{BOLD}Iniciando servidor Streamlit...{RESET}")
    print(f"{CYAN}  Aplicacion: {app_path}{RESET}")
    print(f"{CYAN}  URL: http://localhost:8501{RESET}\n")

    subprocess.run([sys.executable, "-m", "streamlit", "run", str(app_path)])


def main():
    print_header()
    verificar_python()
    print()

    todo_ok = validar_e_instalar()

    if not todo_ok:
        respuesta = input(
            f"\n{YELLOW}Algunas dependencias fallaron. "
            f"¿Desea intentar levantar el servidor de todas formas? (s/n): {RESET}"
        ).strip().lower()
        if respuesta != "s":
            sys.exit(1)

    levantar_streamlit()


if __name__ == "__main__":
    main()