# src/core/face_verifier.py

"""
face_verifier.py

Verificación de identidad facial usando face_recognition (dlib).
Genera encodings de 128 dimensiones por rostro y compara
la distancia euclidiana entre ellos.

A diferencia de dHash, este método sí distingue personas distintas
con alta precisión, que es el requisito del sistema.

Dependencia: pip install face_recognition
             (requiere cmake y dlib — en Windows usar el wheel precompilado)
"""

import hashlib
import pathlib
from io import BytesIO
from typing import Tuple

import numpy as np
from PIL import Image

try:
    import face_recognition
    FACE_RECOGNITION_AVAILABLE = True
except ImportError:
    FACE_RECOGNITION_AVAILABLE = False

# ── Umbral de distancia ────────────────────────────────────────
# face_recognition usa distancia euclidiana entre encodings.
# < 0.45 → misma persona (estricto, recomendado para seguridad)
# < 0.60 → misma persona (tolerante, valor por defecto de la librería)
# Usamos 0.45 para mayor seguridad.
FACE_DISTANCE_THRESHOLD = 0.45
FACE_THRESHOLD          = 1 - FACE_DISTANCE_THRESHOLD   # para mostrar como % de similitud


def _require_face_recognition():
    if not FACE_RECOGNITION_AVAILABLE:
        raise RuntimeError(
            "face_recognition no está instalado.\n"
            "Instale con: pip install face_recognition\n"
            "(En Windows: pip install face_recognition --find-links "
            "https://github.com/jloh02/dlib/releases/)"
        )


# ── Encoding facial ────────────────────────────────────────────

def get_face_encoding(img: Image.Image) -> np.ndarray:
    """
    Genera el encoding de 128 dimensiones del rostro más prominente.
    Lanza ValueError si no detecta ningún rostro.
    """
    _require_face_recognition()

    rgb = np.array(img.convert("RGB"))
    locations = face_recognition.face_locations(rgb, model="hog")

    if not locations:
        raise ValueError(
            "No se detectó ningún rostro en la imagen. "
            "Asegúrese de estar bien iluminado, de frente y centrado en la cámara."
        )

    # Tomar el rostro más grande
    largest = max(locations, key=lambda r: (r[2] - r[0]) * (r[1] - r[3]))
    encodings = face_recognition.face_encodings(rgb, [largest])

    if not encodings:
        raise ValueError("No se pudo calcular el encoding del rostro detectado.")

    return encodings[0]


def encoding_to_bytes(encoding: np.ndarray) -> bytes:
    """Serializa el encoding numpy a bytes para guardar en disco."""
    return encoding.astype(np.float64).tobytes()


def bytes_to_encoding(data: bytes) -> np.ndarray:
    """Deserializa bytes a encoding numpy."""
    return np.frombuffer(data, dtype=np.float64)


# ── Similitud ──────────────────────────────────────────────────

def face_similarity(enc_a: np.ndarray, enc_b: np.ndarray) -> float:
    """
    Convierte distancia euclidiana en score de similitud (0.0 a 1.0).
    Distancia 0.0 → similitud 1.0 (mismo rostro exacto)
    Distancia 0.6 → similitud 0.4 (umbral típico de diferencia)
    """
    distance = float(np.linalg.norm(enc_a - enc_b))
    # Clampear entre 0 y 1
    similarity = max(0.0, 1.0 - distance)
    return round(similarity, 4)


# ── Persistencia ───────────────────────────────────────────────

def compute_face_hash(encoding: np.ndarray) -> str:
    """SHA-256 del encoding serializado — se guarda en DB como referencia."""
    return hashlib.sha256(encoding_to_bytes(encoding)).hexdigest()


def save_face_reference(face_png: bytes, output_path: pathlib.Path) -> None:
    """Guarda el PNG del rostro de referencia en disco."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(face_png)


def save_face_encoding(encoding: np.ndarray, output_path: pathlib.Path) -> None:
    """Guarda el encoding serializado en disco (.enc.bin)."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(encoding_to_bytes(encoding))


def load_face_encoding(enc_path: pathlib.Path) -> np.ndarray:
    """Carga el encoding desde disco."""
    return bytes_to_encoding(enc_path.read_bytes())


# ── Procesamiento de captura ───────────────────────────────────

def process_captured_image(uploaded_file) -> Tuple[np.ndarray, bytes]:
    """
    Recibe el objeto retornado por st.camera_input.
    Detecta el rostro y retorna (encoding, face_png_bytes).

    Lanza ValueError si no detecta ningún rostro.
    """
    img      = Image.open(uploaded_file).convert("RGB")
    encoding = get_face_encoding(img)

    buf = BytesIO()
    img.save(buf, format="PNG")
    face_png = buf.getvalue()

    return encoding, face_png


# ── Verificación ───────────────────────────────────────────────

def verify_face_from_upload(
    encoding_path: pathlib.Path,
    uploaded_file,
    threshold: float = FACE_DISTANCE_THRESHOLD,
) -> Tuple[bool, float]:
    """
    Compara la imagen capturada (st.camera_input) contra el encoding
    de referencia guardado en disco.

    Args:
        encoding_path: ruta al archivo .enc.bin del notario
        uploaded_file: objeto de st.camera_input
        threshold    : distancia máxima permitida (default 0.45)

    Returns:
        (aprobado: bool, score_similitud: float 0.0-1.0)
    """
    _require_face_recognition()

    ref_encoding  = load_face_encoding(encoding_path)
    live_encoding = get_face_encoding(Image.open(uploaded_file).convert("RGB"))

    distance  = float(np.linalg.norm(ref_encoding - live_encoding))
    aprobado  = distance <= threshold
    score     = max(0.0, round(1.0 - distance, 4))

    return aprobado, score