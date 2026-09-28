"""Fuente de verdad única de la política de contraseñas.

Este módulo es el ÚNICO lugar donde vive la política. La interfaz de usuario no
la replica: la descarga de `GET /api/policy` y se construye a partir de esta
respuesta. Eso elimina la divergencia entre servidor y cliente que existía en
la versión anterior, donde el umbral de 12 caracteres aparecía escrito en
cuatro sitios distintos.
"""

from __future__ import annotations

from typing import Any

# Identidad de la política. Un informe de análisis firmado incluye estos
# valores, de modo que months después se puede reproducir exactamente con qué
# reglas se emitió. Es la propiedad que un cliente no puede ofrecer: en el
# navegador, las reglas se pueden editar a voluntad.
POLICY_ID = "upsin-seg-2026-c1"
POLICY_VERSION = "1.0.0"

MIN_LENGTH = 12
MAX_LENGTH = 128

# Umbral de entropía estimada en bits. 40 bits equivale a ~10^12 intentos, que
# a 1e10 intentos/segundo son algo más de 24 horas de cómputo contra un
# atacante con hardware dedicado.
MIN_ENTROPY_BITS = 40.0

# Escala ordinal 0-4 con etiquetas accionables. Los umbrales se derivan de los
# rangos de Log10(guesses) que usa el Apéndice A de NIST SP 800-63B.
SCORE_SCALE: tuple[dict[str, Any], ...] = (
    {"level": 0, "min_bits": 0.0, "label": "Muy débil", "color": "#EF4444"},
    {"level": 1, "min_bits": 28.0, "label": "Débil", "color": "#F59E0B"},
    {"level": 2, "min_bits": 44.0, "label": "Aceptable", "color": "#EAB308"},
    {"level": 3, "min_bits": 60.0, "label": "Fuerte", "color": "#22C55E"},
    {"level": 4, "min_bits": 80.0, "label": "Muy fuerte", "color": "#00FF41"},
)

# Ritmo de ataque asumido para la estimación de tiempo de ruptura: 1e10
# intentos/segundo, que es lo que consigue un clúster de GPUs contra SHA-256
# en modo offline sobre un hash sin sal. Es deliberadamente pesimista: supone
# un atacante con recursos dedicados.
ATTACKS_PER_SECOND = 1e10

# Definición de las reglas mostradas en la interfaz. `kind` le dice al cliente
# cómo renderizar el indicador, pero el cálculo ocurre siempre en el servidor.
RULES: tuple[dict[str, Any], ...] = (
    {
        "id": "length",
        "label": f"Mínimo {MIN_LENGTH} caracteres",
        "kind": "min_length",
        "value": MIN_LENGTH,
    },
    {
        "id": "uppercase",
        "label": "Al menos una mayúscula",
        "kind": "character_class",
        "value": "uppercase",
    },
    {
        "id": "lowercase",
        "label": "Al menos una minúscula",
        "kind": "character_class",
        "value": "lowercase",
    },
    {
        "id": "number",
        "label": "Al menos un número",
        "kind": "character_class",
        "value": "number",
    },
    {
        "id": "symbol",
        "label": "Al menos un símbolo",
        "kind": "character_class",
        "value": "symbol",
    },
    {
        "id": "not_common",
        "label": "No aparece en el diccionario de contraseñas comunes",
        "kind": "corpus",
        "value": None,
    },
    {
        "id": "no_sequence",
        "label": "Sin secuencias ascendentes o descendentes",
        "kind": "pattern",
        "value": "sequence",
    },
    {
        "id": "no_keyboard",
        "label": "Sin recorridos de teclado contiguos",
        "kind": "pattern",
        "value": "keyboard",
    },
    {
        "id": "no_repeat",
        "label": "Sin caracteres o bloques repetidos",
        "kind": "pattern",
        "value": "repeat",
    },
    {
        "id": "no_date",
        "label": "Sin años ni fechas recientes",
        "kind": "pattern",
        "value": "date",
    },
    {
        "id": "entropy",
        "label": f"Al menos {int(MIN_ENTROPY_BITS)} bits estimados",
        "kind": "min_bits",
        "value": MIN_ENTROPY_BITS,
    },
)

# Reglas cuya ausencia invalida el veredicto. La composición por clases se
# mantiene porque es lo que pide la materia, pero aparece POR DEBAJO de la
# estimación de entropía: en la versión anterior, cumplir las cinco reglas
# bastaba, y eso aprobaba `aA1!aA1!aA1!aA1!` que solo tiene 32 combinaciones
# posibles.
CRITICAL_RULE_IDS = frozenset(
    {"length", "not_common", "no_sequence", "no_keyboard", "no_repeat", "entropy"}
)


def rule_by_id(rule_id: str) -> dict[str, Any] | None:
    for rule in RULES:
        if rule["id"] == rule_id:
            return rule
    return None


def score_for_bits(bits: float) -> dict[str, Any]:
    """Traduce una estimación en bits al nivel 0-4 de la escala."""
    selected = SCORE_SCALE[0]
    for entry in SCORE_SCALE:
        if bits >= entry["min_bits"]:
            selected = entry
    return selected


def as_dict(corpus_meta: dict[str, Any] | None = None) -> dict[str, Any]:
    """Representación pública de la política que consume el frontend."""
    payload: dict[str, Any] = {
        "policy_id": POLICY_ID,
        "version": POLICY_VERSION,
        "min_length": MIN_LENGTH,
        "max_length": MAX_LENGTH,
        "min_entropy_bits": MIN_ENTROPY_BITS,
        "attack_assumption": {
            "attempts_per_second": ATTACKS_PER_SECOND,
            "hash": "SHA-256 sin sal, ataque offline",
        },
        "rules": [dict(rule) for rule in RULES],
        "scores": [dict(entry) for entry in SCORE_SCALE],
    }
    if corpus_meta is not None:
        payload["corpus"] = corpus_meta
    return payload
