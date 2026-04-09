# src/core/signature_verifier.py

"""
signature_verifier.py

Verificación de firmas manuscritas usando el método del
Dr. Edwin Gerardo Acuña Acuña (SIGENC-v1):

  1. Renderizar la firma a imagen PIL
  2. Recortar al bounding box del trazo (más estable)
  3. Redimensionar a grilla 32x32
  4. Binarizar con umbral adaptativo (mediana + 20)
  5. Comparar con similitud Jaccard sobre píxeles de tinta

Ventaja sobre SSIM: compara SOLO los píxeles donde hay tinta,
ignorando completamente el fondo blanco — evita falsos positivos.

Umbral: 0.50 (50%) — igual que el código original del profesor.
"""

import hashlib
import pathlib
import numpy as np
from PIL import Image, ImageDraw

SSIM_THRESHOLD = 0.50   # umbral Jaccard mínimo (nombre mantenido por compatibilidad)
GRID           = 32     # tamaño de la grilla de template
MIN_STROKE_PX  = 50     # mínimo de píxeles de tinta para considerar firma válida


# ── Renderizado del canvas ─────────────────────────────────────

def _canvas_to_pil(img_array: np.ndarray) -> Image.Image:
    """
    Convierte el array RGBA del canvas de Streamlit a imagen PIL
    en escala de grises, recortando al bounding box del trazo.
    """
    img = Image.fromarray(img_array.astype("uint8"))

    if img.mode == "RGBA":
        # Fondo blanco para los píxeles transparentes
        background = Image.new("RGB", img.size, (255, 255, 255))
        background.paste(img, mask=img.split()[3])
        img = background.convert("L")
    else:
        img = img.convert("L")

    # Recortar al bounding box del trazo (igual que render_image del profesor)
    bbox = img.point(lambda p: 255 if p > 245 else 0).getbbox()
    if bbox:
        x0, y0, x1, y1 = bbox
        pad = 10
        x0 = max(0, x0 - pad)
        y0 = max(0, y0 - pad)
        x1 = min(img.width,  x1 + pad)
        y1 = min(img.height, y1 + pad)
        img = img.crop((x0, y0, x1, y1))

    return img


def _pil_from_path(path) -> Image.Image:
    """Carga imagen desde disco y la convierte a escala de grises recortada."""
    img = Image.open(path).convert("L")
    bbox = img.point(lambda p: 255 if p > 245 else 0).getbbox()
    if bbox:
        x0, y0, x1, y1 = bbox
        pad = 10
        x0 = max(0, x0 - pad)
        y0 = max(0, y0 - pad)
        x1 = min(img.width,  x1 + pad)
        y1 = min(img.height, y1 + pad)
        img = img.crop((x0, y0, x1, y1))
    return img


# ── Template binario (método del profesor) ─────────────────────

def signature_template_vector(img: Image.Image, grid: int = GRID) -> bytes:
    """
    Convierte la firma a un template binario estable:
      - Redimensiona a grid x grid
      - Binariza con umbral adaptativo (mediana + 20)
      - Retorna bytes de 0/1 (tinta=1, fondo=0)

    Método: Dr. Edwin Gerardo Acuña Acuña (SIGENC-v1)
    """
    img = img.convert("L")
    img = img.resize((grid, grid), resample=Image.BILINEAR)

    px     = list(img.getdata())
    med    = sorted(px)[len(px) // 2]
    thresh = min(230, med + 20)

    bits = bytearray()
    for p in px:
        bits.append(1 if p < thresh else 0)   # tinta = 1

    return bytes(bits)


# ── Similitud Jaccard (método del profesor) ────────────────────

def similarity_ratio(tpl_a: bytes, tpl_b: bytes) -> float:
    """
    Similitud Jaccard sobre píxeles de tinta.
    intersección(tinta_a ∩ tinta_b) / unión(tinta_a ∪ tinta_b)

    0.0 = sin coincidencia, 1.0 = idénticas.

    Método: Dr. Edwin Gerardo Acuña Acuña (SIGENC-v1)
    """
    if len(tpl_a) != len(tpl_b):
        return 0.0

    inter = 0
    union = 0
    for x, y in zip(tpl_a, tpl_b):
        if x == 1 and y == 1:
            inter += 1
        if x == 1 or y == 1:
            union += 1

    if union == 0:
        return 0.0

    return inter / union


# ── Verificación de trazo mínimo ───────────────────────────────

def _count_ink_pixels(template: bytes) -> int:
    return sum(1 for b in template if b == 1)


# ── API pública ────────────────────────────────────────────────

def compute_signature_hash(img_array: np.ndarray) -> str:
    """
    Calcula SHA-256 del template binario.
    Se guarda en DB como referencia.
    """
    pil      = _canvas_to_pil(img_array)
    template = signature_template_vector(pil)
    return hashlib.sha256(template).hexdigest()


def save_reference_image(img_array: np.ndarray, output_path) -> None:
    """
    Guarda la firma de referencia en disco como PNG en escala de grises.
    También guarda el template binario (.bin) para comparación futura.
    """
    out = pathlib.Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    # Guardar imagen visual
    pil = _canvas_to_pil(img_array)
    pil.save(out, format="PNG")

    # Guardar template binario junto a la imagen
    template = signature_template_vector(pil)
    template_path = out.with_suffix(".bin")
    template_path.write_bytes(template)


def compare_signatures(
    reference_path,
    candidate_array: np.ndarray,
    threshold: float = SSIM_THRESHOLD,
) -> tuple[bool, float]:
    """
    Compara la firma de referencia contra la candidata del canvas.

    Args:
        reference_path : ruta al PNG de referencia
        candidate_array: numpy array RGBA del canvas de Streamlit
        threshold      : similitud Jaccard mínima (default 0.50)

    Returns:
        (aprobada: bool, score: float 0.0-1.0)
    """
    # Procesar candidata
    cand_pil      = _canvas_to_pil(candidate_array)
    cand_template = signature_template_vector(cand_pil)

    # Verificar trazo mínimo
    if _count_ink_pixels(cand_template) < MIN_STROKE_PX // (GRID * GRID // 100 + 1):
        return False, 0.0

    # Cargar template de referencia desde .bin si existe, si no generarlo desde PNG
    ref_bin_path = pathlib.Path(reference_path).with_suffix(".bin")
    if ref_bin_path.exists():
        ref_template = ref_bin_path.read_bytes()
    else:
        ref_pil      = _pil_from_path(reference_path)
        ref_template = signature_template_vector(ref_pil)

    score = similarity_ratio(ref_template, cand_template)
    return score >= threshold, round(score, 4)