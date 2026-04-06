# src/core/audit.py

from datetime import datetime
from pathlib import Path

# Archivo donde se guardará la auditoría
LOG = Path("data/audit.log")


def registrar_evento(texto: str):
    """
    Guarda un evento en el log del sistema.
    """

    LOG.parent.mkdir(parents=True, exist_ok=True)

    with open(LOG, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now()} - {texto}\n")