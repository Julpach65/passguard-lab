"""Detección de patrones geométricos: recorridos de teclado, secuencias,
repeticiones y fechas.

Cada detector devuelve `PatternHit`: dónde empieza, cuánto mide y cómo
describirlo. Este módulo NO decide fortaleza, solo encuentra y describe. La
estimación de esfuerzo vive en analyzer.py. La separación existe para que cada
pieza se pueda probar sola.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import NamedTuple

# Normalización a ASCII 1:1 que preserva la longitud. Se usa para que "qwerty"
# con acentos o "áéíóú" se comparen contra las tablas sin desplazar los índices
# que se devuelven al llamador.
_ASCII_FOLD = {
    ord("á"): "a", ord("é"): "e", ord("í"): "i", ord("ó"): "o", ord("ú"): "u",
    ord("ü"): "u", ord("ñ"): "n", ord("Á"): "a", ord("É"): "e", ord("Í"): "i",
    ord("Ó"): "o", ord("Ú"): "u", ord("Ü"): "u", ord("Ñ"): "n",
}


def fold(password: str) -> str:
    """Plegar a ASCII sin alterar la longitud de la cadena."""
    return password.translate(_ASCII_FOLD)


@dataclass(frozen=True)
class PatternHit:
    start: int
    length: int
    kind: str
    detail: str


class _Layout(NamedTuple):
    adjacency: dict[str, frozenset[str]]
    position: dict[str, tuple[int, int]]


def _build_layout(rows: tuple[str, ...]) -> _Layout:
    adjacency: dict[str, set[str]] = {ch: set() for row in rows for ch in row}
    position: dict[str, tuple[int, int]] = {}
    for r, row in enumerate(rows):
        for c, ch in enumerate(row):
            position[ch] = (r, c)
    # Vecindad de 8 direcciones: la CaptchaKey de zxcvbn usa la misma, porque
    # en un teclado real las teclas diagonales también se pulsan por error.
    deltas = ((0, 1), (0, -1), (1, 0), (-1, 0), (1, 1), (1, -1), (-1, 1), (-1, -1))
    for r, row in enumerate(rows):
        for c, ch in enumerate(row):
            for dr, dc in deltas:
                nr, nc = r + dr, c + dc
                if 0 <= nr < len(rows) and 0 <= nc < len(rows[nr]):
                    adjacency[ch].add(rows[nr][nc])
    return _Layout(
        {ch: frozenset(nb) for ch, nb in adjacency.items()},
        position,
    )


# Teclado QWERTY-US y QWERTY-ES. La diferencia relevante es la ñ, que en el
# teclado español ocupa la tecla que en el US es la de la almohadilla.
LAYOUTS: tuple[_Layout, ...] = (
    _build_layout(("1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm")),
    _build_layout(("1234567890", "qwertyuiop", "asdfghjklñ", "zxcvbnm")),
)

# Cadenas de referencia para detectar secuencias ascendentes/descendentes.
SEQUENCES: tuple[str, ...] = (
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiopasdfghjklzxcvbnm",
)

_REPEAT_BLOCK = re.compile(r"(.+?)\1+", re.DOTALL)
_YEAR = re.compile(r"(?<!\d)(?:19\d{2}|20[0-3]\d)(?!\d)")
_DATE_SLASH = re.compile(r"(?<!\d)\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4}(?!\d)")
_DATE_ISO = re.compile(r"(?<!\d)\d{4}-\d{2}-\d{2}(?!\d)")


def _count_turns(run: str, layout: _Layout) -> int:
    """Cuántas veces el dedo cambia de dirección a lo largo del recorrido.

    Es el término que multiplica el esfuerzo: un recorrido recto del mismo
    ancho es vastlyamente más barato de enumerar que uno que zigzaguea.
    """
    directions = []
    for first, second in zip(run, run[1:]):
        a, b = layout.position.get(first), layout.position.get(second)
        if a is None or b is None:
            return 0
        directions.append((b[0] - a[0], b[1] - a[1]))
    if len(directions) < 2:
        return 0
    turns = 0
    for prev, current in zip(directions, directions[1:]):
        # Un giro vertical↔horizontal cuenta como giro; repetir la misma
        # dirección, no.
        if prev[0] != 0 and current[0] != 0 and prev[1] == 0 and current[1] == 0:
            continue
        if prev[1] != 0 and current[1] != 0 and prev[0] == 0 and current[0] == 0:
            continue
        if prev != current:
            turns += 1
    return turns


def find_keyboard_walks(password: str, min_length: int = 3) -> list[PatternHit]:
    """Recorridos contiguos sobre la geometría de un teclado."""
    lowered = fold(password).lower()
    hits: list[PatternHit] = []
    seen: set[tuple[int, int]] = set()

    for layout in LAYOUTS:
        total = len(lowered)
        i = 0
        while i < total - 1:
            if lowered[i + 1] not in layout.adjacency.get(lowered[i], ()):
                i += 1
                continue
            j = i + 1
            while j + 1 < total and lowered[j + 1] in layout.adjacency.get(lowered[j], ()):
                j += 1
            length = j - i + 1
            if length >= min_length and (i, length) not in seen:
                seen.add((i, length))
                fragment = password[i : j + 1]
                turns = _count_turns(lowered[i : j + 1], layout)
                label = f"recorrido de teclado '{fragment}'"
                if turns:
                    label += f" con {turns} giro{'s' if turns != 1 else ''}"
                hits.append(PatternHit(i, length, "keyboard", label))
            i = j
    return hits


def find_sequences(password: str, min_length: int = 3) -> list[PatternHit]:
    """Series ascendentes o descendentes dentro de tablas conocidas."""
    lowered = fold(password).lower()
    hits: list[PatternHit] = []
    seen: set[tuple[int, int]] = set()

    for sequence in SEQUENCES:
        index = {ch: pos for pos, ch in enumerate(sequence)}
        total = len(lowered)
        i = 0
        while i < total - 1:
            a, b = index.get(lowered[i]), index.get(lowered[i + 1])
            if a is None or b is None or abs(b - a) != 1:
                i += 1
                continue
            step = 1 if b > a else -1
            j = i + 1
            while j + 1 < total:
                nxt = index.get(lowered[j + 1])
                if nxt is None or nxt - index[lowered[j]] != step:
                    break
                j += 1
            length = j - i + 1
            if length >= min_length and (i, length) not in seen:
                seen.add((i, length))
                fragment = password[i : j + 1]
                sense = "ascendente" if step > 0 else "descendente"
                hits.append(PatternHit(i, length, "sequence", f"secuencia {sense} '{fragment}'"))
            i = j
    return hits


def find_repeats(password: str, min_length: int = 3) -> list[PatternHit]:
    """Bloques repetidos de forma inmediata: 'aaaa', 'abcabc', '121212'."""
    hits: list[PatternHit] = []
    for match in _REPEAT_BLOCK.finditer(password):
        block = match.group(1)
        length = len(match.group(0))
        if length < min_length or not block:
            continue
        times = length // len(block)
        if times < 2:
            continue
        if len(block) == 1:
            detail = f"carácter '{block}' repetido {times} veces"
        else:
            detail = f"bloque '{block}' repetido {times} veces"
        hits.append(PatternHit(match.start(), length, "repeat", detail))
    return hits


def find_dates(password: str) -> list[PatternHit]:
    """Años y fechas. Los años son el descriptor personal más habitual."""
    hits: list[PatternHit] = []
    occupied: list[tuple[int, int]] = []

    for match in _DATE_ISO.finditer(password):
        hits.append(
            PatternHit(match.start(), len(match.group(0)), "date", f"fecha ISO '{match.group(0)}'")
        )
        occupied.append((match.start(), match.end()))

    for match in _DATE_SLASH.finditer(password):
        if any(match.start() < end and start < match.end() for start, end in occupied):
            continue
        hits.append(
            PatternHit(match.start(), len(match.group(0)), "date", f"fecha '{match.group(0)}'")
        )
        occupied.append((match.start(), match.end()))

    for match in _YEAR.finditer(password):
        if any(match.start() < end and start < match.end() for start, end in occupied):
            continue
        hits.append(PatternHit(match.start(), 4, "date", f"año '{match.group(0)}'"))
    return hits


def normalize(password: str) -> str:
    """NFC, para que las letras compuestas no cuenten como caracteres raros."""
    return unicodedata.normalize("NFC", password)


def nfc_len(password: str) -> int:
    return len(unicodedata.normalize("NFC", password))
