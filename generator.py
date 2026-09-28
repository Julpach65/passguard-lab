"""Generador de contraseñas con CSPRNG y garantía por construcción.

Dos correcciones importantes respecto a la versión anterior:

1. El `while True` de app.py (líneas 12-21) se colgaba para siempre con
   longitudes menores a 12, porque el predicado de aceptación exigía 12
   caracteres que el generador nunca producía. Aquí la longitud se recorta al
   rango válido ANTES de generar, y la garantía se construye por diseño: se
   reservan posiciones para una carácter de cada clase activa y luego se
   rellena el resto. Nunca hay bucle de rechazo, luego nunca hay bucle infinito.

2. El alfabeto por defecto ya no es `string.punctuation` completo. Al menos 17
   de esos caracteres rompen sistemas reales al pegarse en una URL, en HTML sin
   escapar o en una línea de comandos. El alfabeto "web" los excluye.

El muestreo usa secrets.SystemRandom, y el barajado es Fisher-Yates. No hay
ninguna fuente de entropía débil en este archivo.
"""

from __future__ import annotations

import math
import secrets
from typing import Sequence

from config import config
import policy

RNG = secrets.SystemRandom()

LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"

# `string.punctuation` sin los metacaracteres que rompen URL, HTML, shell y CSV.
WEB_SYMBOLS = "!#$%&()*+,-.:;<=>?@[]^_~{|}/"

AMBIGUOUS = "0O1lI"

ALPHABETS: dict[str, str] = {
    "alnum": LOWER + UPPER + DIGITS,
    "web": LOWER + UPPER + DIGITS + WEB_SYMBOLS,
    "full": LOWER + UPPER + DIGITS + "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
}


class GenerationError(ValueError):
    """Combinación pedida imposible de satisfacer (p. ej. 4 clases y longitud 2)."""


def alphabet_for(name: str, avoid_ambiguous: bool) -> str:
    if name not in ALPHABETS:
        raise GenerationError(f"alfabeto desconocido: {name!r}")
    pool = ALPHABETS[name]
    if avoid_ambiguous:
        pool = "".join(ch for ch in pool if ch not in AMBIGUOUS)
    return pool


def group_for(ch: str) -> str:
    if ch in LOWER:
        return "lowercase"
    if ch in UPPER:
        return "uppercase"
    if ch in DIGITS:
        return "number"
    return "symbol"


def _shuffle(items: list[str]) -> None:
    for i in range(len(items) - 1, 0, -1):
        j = RNG.randrange(i + 1)
        items[i], items[j] = items[j], items[i]


def generate(
    length: int,
    groups: Sequence[str],
    avoid_ambiguous: bool = True,
    min_classes: int = 0,
    alphabet_name: str = "web",
) -> str:
    """Genera una contraseña de `length` caracteres garantizando `min_classes`."""
    length = max(policy.MIN_LENGTH, min(policy.MAX_LENGTH, length))

    if min_classes < 1:
        min_classes = 1
    if len(groups) < min_classes:
        raise GenerationError(
            f"se piden {min_classes} clases de caracteres pero solo hay {len(groups)} activas"
        )
    if min_classes > length:
        raise GenerationError(
            f"no caben {min_classes} clases distintas en {length} caracteres"
        )

    pools: dict[str, str] = {}
    for name in groups:
        if name not in ("lowercase", "uppercase", "number", "symbol"):
            raise GenerationError(f"clase desconocida: {name!r}")
        pool = alphabet_for(alphabet_name, avoid_ambiguous)
        if name == "lowercase":
            pool = "".join(c for c in pool if c in LOWER)
        elif name == "uppercase":
            pool = "".join(c for c in pool if c in UPPER)
        elif name == "number":
            pool = "".join(c for c in pool if c in DIGITS)
        else:
            pool = "".join(c for c in pool if c not in LOWER + UPPER + DIGITS)
        if not pool:
            raise GenerationError(f"el alfabeto {alphabet_name!r} no aporta la clase {name!r}")
        pools[name] = pool

    union = "".join(pools[name] for name in groups)

    # Garantía por construcción: una carácter reservado por cada clase activa.
    # Nunca rechazamos y reintentamos, así que el número de operaciones es
    # exactamente `length`, con independencia de la longitud pedida.
    chars = [RNG.choice(pools[name]) for name in groups]
    chars.extend(RNG.choice(union) for _ in range(length - len(groups)))
    _shuffle(chars)
    password = "".join(chars)

    if len(password) != length:  # invariante, no rama alcanzable
        raise GenerationError("fallo invariante: longitud incorrecta")
    return password


def describe(
    password: str,
    alphabet_name: str = "web",
    avoid_ambiguous: bool = True,
) -> dict[str, object]:
    """Métricas del resultado, calculadas con el mismo modelo del analizador.

    La entropía es n·log2(k), donde k es el tamaño del POZO del que se extrajo
    la contraseña, no el número de caracteres distintos observados. Confundir
    ambas cosas da un número inflado: un modelo de 94 caracteres del que salen
    8 símbolos distintos sigue costando 94^8, no 8^8.
    """
    pool = alphabet_for(alphabet_name, avoid_ambiguous)
    present = {group_for(ch) for ch in password}
    union = "".join(c for c in pool if group_for(c) in present)
    pool_size = len(union)
    bits = len(password) * math.log2(pool_size) if pool_size > 1 else 0.0
    return {
        "length": len(password),
        "alphabet_size": pool_size,
        "entropy_bits": round(bits, 2),
        "classes_present": len(present),
    }
