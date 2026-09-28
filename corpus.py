"""Carga perezosa del diccionario de contraseñas comunes, con su ranking.

Por qué vive en el servidor y no en el cliente: el corpus pesa megabytes, el
navegador tendría que descargarlo entero, y peor aún, podría modificarlo para
falsear el veredicto a su antojo. Un cliente no es una autoridad. El servidor
sí lo es.

El archivo esperado es `data/corpus.txt`: una contraseña por línea, en orden de
frecuencia descendente, de modo que el número de línea ES el ranking. Se genera
con scripts/build_corpus.py y su sha256 se publica en /api/policy para que un
análisis sea reproducible meses después.

Si el archivo no está, el módulo degrada a corpus vacío y lo reporta. La app
sigue funcionando: solo pierde la detección de contraseñas conocidas.
"""

from __future__ import annotations

import hashlib
import os
import threading

CORPUS_NAME = "common-passwords-es"

_lock = threading.Lock()
_cache: dict[str, int] | None = None
_meta: dict[str, object] | None = None


def _read(path: str) -> dict[str, int]:
    ranks: dict[str, int] = {}
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for offset, line in enumerate(handle, start=1):
            token = line.strip()
            if not token or token.startswith("#"):
                continue
            ranks.setdefault(token, offset)
    return ranks


def _digest(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load(path: str) -> dict[str, int]:
    """Devuelve el mapa contraseña -> ranking, cargándolo una sola vez."""
    global _cache, _meta
    with _lock:
        if _cache is None:
            if os.path.isfile(path):
                ranks = _read(path)
                _meta = {
                    "name": CORPUS_NAME,
                    "size": len(ranks),
                    "sha256": _digest(path),
                    "loaded": True,
                }
            else:
                ranks = {}
                _meta = {
                    "name": CORPUS_NAME,
                    "size": 0,
                    "sha256": None,
                    "loaded": False,
                    "note": "corpus ausente; la deteccion de contrasenas comunes esta desactivada",
                }
            _cache = ranks
        return _cache


def metadata(path: str) -> dict[str, object]:
    load(path)
    assert _meta is not None
    return dict(_meta)


def rank_of(word: str, path: str) -> int | None:
    """Ranking de una palabra exacta, o None si no está en el corpus."""
    return load(path).get(word)


def lookup_substrings(password: str, path: str, min_length: int = 4) -> list[tuple[int, int, int]]:
    """Encuentra el segmento más guessable de la contraseña.

    Busca, para cada posición de inicio, la palabra del corpus más larga que
    encaje ahí. Devuelve (inicio, longitud, ranking). Exige min_length porque
    una coincidencia de tres letras dentro de una palabra larga es ruido, no
    señal.

    El ranking es la clave del modelo: una palabra en la posición 3 del
    diccionario se adivina en 3 intentos, sin importar que la contraseña
    entera sea larga. Por eso la longitud no protege cuando lo adivinable es obvio.
    """
    ranks = load(path)
    if not ranks:
        return []
    lowered = password.lower()
    found: list[tuple[int, int, int]] = []
    for start in range(len(lowered)):
        best: tuple[int, int, int] | None = None
        limit = min(len(lowered), start + 16)
        for end in range(limit, start + min_length - 1, -1):
            rank = ranks.get(lowered[start:end])
            if rank is not None:
                best = (start, end - start, rank)
                break
        if best is not None:
            found.append(best)
    return found
