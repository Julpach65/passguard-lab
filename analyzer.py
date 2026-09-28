"""Analizador de fortaleza de contraseñas.

Modelo: reimplementación en Python del enfoque de zxcvbn / Apéndice A de
NIST SP 800-63B. No se usa ninguna biblioteca externa.

La idea central, y lo que separa esto de un checklist de cinco Casillas: un
atacante elige el ataque MÁS BARATO, no el más evidente. Por eso el esfuerzo se
estima como el MÍNIMO entre dos estrategias:

    1. Fuerza bruta: probar las combinaciones del espacio completo.
    2. romPe<pattern>: adivinar el segmento predecible (una palabra del
       diccionario, un recorrido de teclado, un año) y luego recorrer el resto.

La estrategia 2 siempre gana o iguala a la 1 en cuanto hay un patrón. Y por
eso una contraseña de 16 caracteres con "password" dentro tiene muy pocos bits,
aunque su longitud sea respetable. La longitud protege SOLO cuando el contenido
es realmente impredecible.

Consecuencia deliberately incómoda para el usuario: las cinco reglas de
composición (mayúscula, minúscula, número, símbolo) NO aparecen entre las reglas
críticas, porque la evidencia dice que importan mucho menos que el tamaño del
espacio de búsqueda. Siguen mostrándose como orientación.
"""

from __future__ import annotations

import itertools
import math
import unicodedata
from typing import Any

import patterns
import policy
from config import config

# Sustituciones l33t. El orden importa: se generan todas las variantes y se
# cuentan las que existen en el diccionario, y ese recuento es el multiplicador
# de esfuerzo. `P4$$w0rd` tiene 8 variantes legítimas, luego cuesta 8 veces más
# que `password` — pero sigue siendo una contraseña de_force-bruta.
L33T_TABLE: dict[str, tuple[str, ...]] = {
    "1": ("l", "i"),
    "!": ("i",),
    "0": ("o",),
    "3": ("e",),
    "4": ("a",),
    "@": ("a",),
    "5": ("s",),
    "$": ("s",),
    "7": ("t",),
    "8": ("b",),
    "9": ("g",),
    "|": ("l", "i"),
}

MAX_L33T_VARIANTS = 128

# Tamaño del alfabeto global según las clases presentes. Es el factor que se
# aplica a los caracteres "sobrantes" de una estrategia dirigida.
# Tamaño real de cada clase, no el número de clases. La versión anterior usaba
# una tabla {1: 26, 2: 52, 3: 62, 4: 94} que asumía que dos clases siempre
# significaban minúsculas + mayúsculas. Así `abcabc1`, que solo trae
# minúsculas y un dígito, recibía 52 en vez de 36: 2.7 bits de sobra por
# carácter, unos 16 bits en una contraseña de 6.
_LOWER_SIZE = 26
_UPPER_SIZE = 26
_DIGIT_SIZE = 10
_SYMBOL_SIZE = 32


def _l33t_variants(segment: str) -> list[str]:
    """Variantes no-sustituidas de un segmento, acotadas por seguridad.

    `p4ssw0rd` produce cuatro candidatos: p4ssw0rd, p4ssword, passw0rd y
    password. Las tres últimas existen en el diccionario, luego al atacante le
    cuesta varias veces más probar `p4ssw0rd` que `password` a secas. El
    producto de itertools es perezoso, así que el corte por
    MAX_L33T_VARIANTS no obliga a materializar la explosión combinatoria.
    """
    lowered = segment.lower()
    if not any(ch in L33T_TABLE for ch in lowered):
        return [lowered]

    options: list[list[str]] = []
    for ch in lowered:
        if ch in L33T_TABLE:
            options.append([ch, *L33T_TABLE[ch]])
        else:
            options.append([ch])

    variants: list[str] = []
    for combo in itertools.product(*options):
        variants.append("".join(combo))
        if len(variants) >= MAX_L33T_VARIANTS:
            break
    return variants


def _charset_size(password: str) -> int:
    return len(set(password))

def _global_alphabet(password: str) -> int:
    """Tamaño del alfabeto que el atacante tendría que recorrer por fuerza bruta.

    Reutiliza `_character_classes` a propósito. Antes esta función repetía la
    definición de "símbolo" con `not c.isalnum()`, y el guion.countaba como
    símbolo aquí pero no en la regla de la política: la misma palabra valía
    para un cálculo y no para el otro. Una sola definición, un solo veredicto.
    """
    classes = _character_classes(password)
    size = 0
    if classes["lowercase"]:
        size += _LOWER_SIZE
    if classes["uppercase"]:
        size += _UPPER_SIZE
    if classes["number"]:
        size += _DIGIT_SIZE
    if classes["symbol"]:
        size += _SYMBOL_SIZE
    # Sin ninguna clase no se puede estimar nada; se usa el mínimo plausible.
    return size or _LOWER_SIZE


def human_duration(seconds: float) -> str:
    """Traduce segundos a lenguaje natural, sin exagerar ni esconder."""
    if seconds < 1:
        return "menos de un segundo"
    if seconds < 60:
        return f"{seconds:.0f} segundos"
    if seconds < 3600:
        return f"{seconds / 60:.0f} minutos"
    if seconds < 86400:
        return f"{seconds / 3600:.0f} horas"
    if seconds < 2592000:
        return f"{seconds / 86400:.0f} días"
    if seconds < 31536000:
        return f"{seconds / 2592000:.0f} meses"
    years = seconds / 31536000
    if years < 1000:
        return f"{years:.0f} años"
    if years < 1_000_000:
        return f"{years / 1000:.0f} milenios"
    if years < 1_000_000_000:
        return f"{years / 1_000_000:.0f} millones de años"
    return "tiempo geológico"


def _mask(password: str, start: int, length: int) -> str:
    return f"{password[:start]}[patrón]{password[start + length:]}"


def _find_dictionary(password: str) -> list[dict[str, Any]]:
    """Segmentos explicables por el diccionario, incluido vía l33t.

    Para cada posición de inicio busca la coincidencia MÁS LARGA, porque un
    segmento largo con buen ranking es más barato de romper que uno corto
    con ranking mediocre.
    """
    import corpus

    findings: list[dict[str, Any]] = []
    lowered = password.lower()
    total = len(lowered)
    claimed: list[tuple[int, int]] = []

    for start in range(total):
        for end in range(min(total, start + 16), start + 3, -1):
            segment = lowered[start:end]
            best_rank: int | None = None
            matched = 0
            for variant in _l33t_variants(segment):
                rank = corpus.rank_of(variant, config.corpus_path)
                if rank is None:
                    continue
                matched += 1
                if best_rank is None or rank < best_rank:
                    best_rank = rank

            if best_rank is None:
                continue

            length = end - start
            if any(start < ce and cs < end for cs, ce in claimed):
                break
            claimed.append((start, end))

            multiplier = max(1, matched)
            guesses = best_rank * multiplier
            severity = "critical" if best_rank <= 1000 else "high"
            original = password[start:end]
            l33t_note = (
                f", {multiplier} variantes por sustitución l33t" if multiplier > 1 else ""
            )
            findings.append(
                {
                    "id": "dictionary",
                    "severity": severity,
                    "label": f"Contiene «{original}», una contraseña común",
                    "detail": f"ranking {best_rank} en el diccionario{l33t_note}",
                    "start": start,
                    "length": length,
                    "guesses": guesses,
                    "masked": _mask(password, start, length),
                }
            )
            break
    return findings


def _guess_cost(hit: patterns.PatternHit, password: str) -> float:
    """Estimación de intentos para romper SOLO ese patrón.

    Las constantes siguen el orden de magnitud que usa zxcvbn: la enumeración de
    un recorrido de teclado es barata (unas miles de combinaciones), la de una
    fecha es carísima en comparación, y la fuerza bruta del resto domina.
    """
    if hit.kind == "keyboard":
        turns = 0
        lowered = patterns.fold(password[hit.start : hit.start + hit.length]).lower()
        for layout in patterns.LAYOUTS:
            turns = max(turns, patterns._count_turns(lowered, layout))
        return max(4.0, hit.length * (1.0 + turns) * 10.0)
    if hit.kind == "sequence":
        return max(4.0, hit.length * 4.0)
    if hit.kind == "repeat":
        return _repeat_guesses(password[hit.start : hit.start + hit.length])
    if hit.kind == "date":
        return 365.0 if hit.length > 4 else 3000.0
    return 1000.0


def _repeat_guesses(segment: str) -> float:
    """Intentos para romper un bloque repetido.

    No basta con la longitud. En `aA1!aA1!aA1!aA1!` el atacante elige los 4
    caracteres del bloque una vez y las repeticiones se las regalan: el espacio
    de búsqueda es |alfabeto_del_bloque|^veces, o sea 4^4 = 256, y no 2^32 ni
    tampoco 16 (que es solo el número de posiciones).
    """
    if not segment:
        return 3.0

    for block_length in range(1, len(segment) // 2 + 1):
        if len(segment) % block_length:
            continue
        block = segment[:block_length]
        if segment == block * (len(segment) // block_length):
            times = len(segment) // block_length
            # El atacante elige el contenido del bloque y luego solo repetir.
            return float(len(set(block)) ** times) if len(set(block)) > 1 else 1.0

    # Sin bloque limpio: se comporta como un alfabeto plano de la longitud.
    return float(max(2, len(set(segment))) ** max(1, len(segment) // 2))


def _pattern_findings(password: str) -> list[dict[str, Any]]:
    hits: list[patterns.PatternHit] = []
    hits += patterns.find_keyboard_walks(password)
    hits += patterns.find_sequences(password)
    hits += patterns.find_repeats(password)
    hits += patterns.find_dates(password)

    findings: list[dict[str, Any]] = []
    for hit in sorted(hits, key=lambda h: (-h.length, h.start)):
        severity = "high"
        if hit.length >= 5:
            severity = "critical"
        elif hit.kind == "date":
            severity = "medium"
        elif hit.length == 3:
            severity = "low"
        findings.append(
            {
                "id": hit.kind,
                "severity": severity,
                "label": hit.detail.capitalize(),
                "detail": f"patrón de {hit.length} caracteres en la posición {hit.start + 1}",
                "start": hit.start,
                "length": hit.length,
                "guesses": _guess_cost(hit, password),
                "masked": _mask(password, hit.start, hit.length),
            }
        )
    return findings


def _is_symbol(ch: str) -> bool:
    """¿Este carácter cuenta como símbolo para la política?

    No basta con `not ch.isalnum()`: eso hacía que el guion, el punto y la coma
    cumplieran el requisito de símbolo, y `clave-de-seguridad-larga` pasaba los
    cinco criterios de la versión anterior sin un solo símbolo de verdad.

    La regla es: impreso, no alfanumérico, no espacio, y además que no sea un
    conector de palabras. Los conectores son la categoría Pd (guiones) y Pc
    (guion bajo), más los espacios de separación. Se excluyen porque su función
    es unir palabras dentro de una frase, no añadir entropía: `mi-clave` y
    `mi_clave` son la misma contraseña con otro trazo.

    Por eso `!`, `@`, `#`, `$`, `%`, `*` y los paréntesis sí cuentan, y el
    guion no. No hay forma limpia de distinguirlos por la categoría general de
    Unicode, porque `!` y `.` comparten la misma (Po); la excepción se hace
    explícita sobre el conector, que es el caso que realmente importa.
    """
    if ch.isalnum() or ch.isspace() or not ch.isprintable():
        return False
    return unicodedata.category(ch) not in ("Pd", "Pc")


def _character_classes(password: str) -> dict[str, bool]:
    return {
        "uppercase": any(c.isupper() for c in password),
        "lowercase": any(c.islower() for c in password),
        "number": any(c.isdigit() for c in password),
        "symbol": any(_is_symbol(c) for c in password),
    }


def _explanation(bits: float, score: dict[str, Any], findings: list[dict[str, Any]], length: int) -> str:
    if not findings:
        return (
            f"No se detectan patrones predecibles. Con {length} caracteres y un alfabeto "
            f"de {round(bits / max(length, 1))} bits por posición, el espacio de búsqueda es "
            f"de {bits:.0f} bits: un atacante necesitaría un tiempo {'incalculable' if bits > 90 else 'muy largo'} "
            f"en hardware dedicado."
        )
    worst = findings[0]
    pieces = [
        f"El veredicto es «{score['label']}» con {bits:.0f} bits estimados.",
        f"El factor dominante es: {worst['label'].lower()}.",
    ]
    others = sorted({f["label"] for f in findings[1:]})
    if others:
        pieces.append("También se detectaron: " + "; ".join(others[:3]).lower() + ".")
    return " ".join(pieces)


def analyze(password: str, context: list[str] | None = None) -> dict[str, Any]:
    """Punto de entrada. Devuelve el análisis completo y explicable."""
    original = password
    password = patterns.normalize(password)
    length = len(password)

    classes = _character_classes(password)
    findings = _find_dictionary(password) + _pattern_findings(password)

    if context:
        for term in context:
            clean = patterns.fold(term).lower()
            if len(clean) < 3:
                continue
            index = password.lower().find(clean)
            if index >= 0:
                findings.append(
                    {
                        "id": "context",
                        "severity": "critical",
                        "label": f"Contiene «{term}», un dato de contexto que no es un secreto",
                        "detail": "los nombres y fechas personales no sonentropy: están en cualquier lista de correo filtrado",
                        "start": index,
                        "length": len(clean),
                        "guesses": 100.0,
                        "masked": _mask(password, index, len(clean)),
                    }
                )

    charset = _charset_size(password)
    global_alphabet = _global_alphabet(password)
    brute_force = float(global_alphabet) ** length if length else 1.0

    directed = brute_force
    for finding in findings:
        remaining = max(length - finding["length"], 0)
        candidate = finding["guesses"] * (float(global_alphabet) ** remaining)
        directed = min(directed, candidate)

    guesses = max(min(brute_force, directed), 1.0)
    bits = math.log2(guesses) if guesses > 0 else 0.0
    guesses_log10 = math.log10(guesses) if guesses > 0 else 0.0

    score = policy.score_for_bits(bits)
    crack_seconds = guesses / policy.ATTACKS_PER_SECOND

    checks: dict[str, bool] = {
        "length": length >= policy.MIN_LENGTH,
        **classes,
        "not_common": not any(f["id"] == "dictionary" for f in findings),
        "no_sequence": not any(f["id"] == "sequence" for f in findings),
        "no_keyboard": not any(f["id"] == "keyboard" for f in findings),
        "no_repeat": not any(f["id"] == "repeat" for f in findings),
        "no_date": not any(f["id"] == "date" for f in findings),
        "entropy": bits >= policy.MIN_ENTROPY_BITS,
    }

    failed = [rule_id for rule_id in policy.CRITICAL_RULE_IDS if not checks.get(rule_id, True)]
    missing = [policy.rule_by_id(rid)["label"] for rid in failed if policy.rule_by_id(rid)]

    ordered = sorted(
        findings,
        key=lambda f: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f["severity"], 4),
            f["start"],
        ),
    )

    return {
        "password_length": len(original),
        "policy_id": policy.POLICY_ID,
        "policy_version": policy.POLICY_VERSION,
        "valid": not failed,
        "checks": checks,
        "missing": missing,
        "rules": [
            {**{k: v for k, v in policy.rule_by_id(rid).items()}, "ok": checks.get(rid, False)}
            for rid in (r["id"] for r in policy.RULES)
            if policy.rule_by_id(rid)
        ],
        "score": score["level"],
        "score_label": score["label"],
        "score_color": score["color"],
        "entropy_bits": round(bits, 2),
        "charset_size": charset,
        "global_alphabet": global_alphabet,
        "guesses_log10": round(guesses_log10, 3),
        "crack_time": {
            "seconds": crack_seconds,
            "human": human_duration(crack_seconds),
            "attempts_per_second": policy.ATTACKS_PER_SECOND,
            "assumption": "SHA-256 sin sal, ataque offline, 1 GPU de alto rendimiento",
        },
        "findings": ordered,
        "explanation": _explanation(bits, score, ordered, length),
        "source": "server",
    }
