# src/core/pdf_stamp.py

"""
pdf_stamp.py

Estampa una línea de texto en la esquina inferior derecha de cada
página del PDF. Sin fondo ni bordes — solo texto semitransparente.

Soporta offset_y para apilar múltiples firmas sin sobreescribirse.
"""

import io
import pathlib

from reportlab.lib import colors
from reportlab.pdfgen import canvas as rl_canvas
from pypdf import PdfReader, PdfWriter

MARGEN   = 12    # distancia al borde
FONT     = "Helvetica-Oblique"
FONT_SZ  = 8
LINE_GAP = 14    # separación vertical entre líneas de firma


def _crear_pagina_sello(
    page_width: float,
    page_height: float,
    firmante: str,
    offset_y: int = 0,
) -> bytes:
    """
    Genera una página PDF transparente con una línea de texto
    en la esquina inferior derecha.

    Args:
        offset_y: desplazamiento vertical en puntos hacia arriba.
                  0 = primera firma (empleado), 14 = segunda (empresa), etc.
    """
    buf = io.BytesIO()
    c   = rl_canvas.Canvas(buf, pagesize=(page_width, page_height))

    texto  = f"Firmado digitalmente por {firmante}"

    c.setFont(FONT, FONT_SZ)
    c.setFillColor(colors.Color(0.3, 0.3, 0.3, alpha=0.7))

    text_w = c.stringWidth(texto, FONT, FONT_SZ)
    x = page_width - text_w - MARGEN
    y = MARGEN + offset_y

    c.drawString(x, y, texto)
    c.save()
    buf.seek(0)
    return buf.read()


def estampar_firma(
    pdf_path: pathlib.Path,
    output_path: pathlib.Path,
    firmante: str,
    offset_y: int = 0,
    **kwargs,
) -> pathlib.Path:
    """
    Lee el PDF, estampa el texto en cada página y guarda en output_path.

    Args:
        pdf_path   : ruta al PDF de entrada (puede ser el ya sellado)
        output_path: ruta donde guardar el PDF resultante
        firmante   : texto a mostrar como firmante
        offset_y   : desplazamiento vertical para no solapar firmas anteriores
                     usar LINE_GAP * n donde n es el número de firma (0-based)
    Returns:
        output_path
    """
    reader = PdfReader(str(pdf_path))
    writer = PdfWriter()

    for page in reader.pages:
        page_width  = float(page.mediabox.width)
        page_height = float(page.mediabox.height)

        sello_bytes = _crear_pagina_sello(page_width, page_height, firmante, offset_y)
        sello_page  = PdfReader(io.BytesIO(sello_bytes)).pages[0]

        page.merge_page(sello_page)
        writer.add_page(page)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as f:
        writer.write(f)

    return output_path