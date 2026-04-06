# src/core/qr_module.py

import qrcode
from pathlib import Path


def generar_qr(data: str, output_path: str):
    """
    Genera un código QR con la información enviada.

    Args:
        data: texto a codificar (hash, id contrato, etc)
        output_path: ruta donde se guardará el QR
    """

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    qr = qrcode.QRCode(
        version=1,
        box_size=10,
        border=4
    )

    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    img.save(output)