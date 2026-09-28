"""Pruebas del analizador, orientadas a los errores que la versión anterior tenía.

Cada caso de este archivo reproduce un fallo concreto del primer corte. Si
alguien reintroduce el error, la prueba cae.
"""

from __future__ import annotations

import pytest

import analyzer
import policy


# --- Errores 1: el verificador anterior APPROBABA esto ------------------------


def test_repeated_block_is_rejected():
    """`aA1!aA1!aA1!aA1!` solo tiene 4^4 = 256 combinaciones, no 32 bits.

    La versión anterior la daba por válida con 32 bits estimados, cuando en
    realidad el espacio de búsqueda es minúsculo.
    """
    result = analyzer.analyze("aA1!aA1!aA1!aA1!")
    assert not result["valid"]
    assert result["entropy_bits"] < 10
    assert result["score"] == 0
    assert any(f["id"] == "repeat" for f in result["findings"])


def test_repeated_block_finds_are_cheap():
    """El ataque mínimo debe estar en el orden de 4^4 = 256, no de 2^32.

    `guesses_log10` es el número que la interfaz muestra; 1.204 equivale a
    16 posiciones, pero el ataque real son las 256 combinaciones del bloque.
    """
    result = analyzer.analyze("aA1!aA1!aA1!aA1!")
    assert 10 ** result["guesses_log10"] < 1_000_000
    assert result["entropy_bits"] < 10
    repeat = [f for f in result["findings"] if f["id"] == "repeat"]
    assert repeat
    assert repeat[0]["guesses"] <= 256


# --- Errores 2: el verificador anterior RECHAZABA esto ----------------------


def test_long_passphrase_is_accepted():
    """`correcthorsebatterystaple` vale ~118 bits en el modelo del analizador.

    La versión anterior lo rechazaba con "no cumple los criterios" porque
    buscaba símbolos y un guion no cuenta como símbolo.
    """
    result = analyzer.analyze("correcthorsebatterystaple")
    assert result["valid"]
    assert result["entropy_bits"] > 60
    assert result["score"] >= 3


# --- Errores 3: un guion NO es un símbolo, un espacio tampoco ---------------


def test_hyphen_is_not_a_symbol():
    result = analyzer.analyze("clave-de-seguridad-larga")
    assert not result["checks"]["symbol"]


def test_space_does_not_count_as_symbol():
    result = analyzer.analyze("abc abc1")
    assert not result["checks"]["symbol"]


def test_real_symbol_is_counted():
    result = analyzer.analyze("abc abc1!")
    assert result["checks"]["symbol"]


def test_hyphen_does_not_widen_the_alphabet():
    """    El alfabeto global se deriva de las MISMAS clases que la política, sumando
    el tamaño de cada una (26 minúsculas, 26 mayúsculas, 10 dígitos, 32
    símbolos). La tabla anterior solo miraba cuántas clases había y asumía
    minúsculas + mayúsculas, así que inflaba las contraseñas de letras y
    dígitos. La comprobación ata la regla de la política al cálculo de
    entropía, que es donde antes divergían.
    """
    assert analyzer.analyze("clave-de-seguridad-larga")["global_alphabet"] == 26
    assert analyzer.analyze("abcabc1")["global_alphabet"] == 36
    assert analyzer.analyze("abcabc1A")["global_alphabet"] == 62
    assert analyzer.analyze("abcabc1!")["global_alphabet"] == 68
    assert analyzer.analyze("abcABC123!")["global_alphabet"] == 94


def test_space_run_is_flagged_as_repeat():
    result = analyzer.analyze("          aA1!")
    assert any(f["id"] == "repeat" for f in result["findings"])


# --- Errores 4: detección de diccionario y l33t ----------------------------


@pytest.mark.parametrize(
    "password, must_contain",
    [
        ("1234567890 aB", "1234567890"),
        ("qwertyuiop", "qwertyuiop"),
        ("admin", "admin"),
        ("julieta2024", "julieta"),
    ],
)
def test_known_common_passwords_are_found(password, must_contain):
    result = analyzer.analyze(password)
    assert not result["valid"]
    hits = [f for f in result["findings"] if f["id"] == "dictionary"]
    assert hits, f"no se detectó diccionario en {password!r}"
    assert any(must_contain in f["label"] for f in hits)


def test_l33t_variant_is_unmasked():
    """`P4$$w0rd` es `password` disfrazado; debe bajar a bitsridículos."""
    result = analyzer.analyze("P4$$w0rd")
    assert any(f["id"] == "dictionary" for f in result["findings"])
    assert result["entropy_bits"] < 20
    assert not result["valid"]


def test_l33t_multiplier_costs_more_than_plain():
    """La versión l33t debe costar MÁS intentos que la literal.

    Se comparan los `guesses` de las findings, que es donde vive el
    multiplicador; `guesses_log10` de la raíz es el mínimo entre todos los
    patrones y no refleja esa diferencia.
    """
    def dictionary_guesses(password: str) -> float:
        hits = [
            f["guesses"]
            for f in analyzer.analyze(password)["findings"]
            if f["id"] == "dictionary"
        ]
        return max(hits) if hits else 0.0

    assert dictionary_guesses("p4ssw0rd") > dictionary_guesses("password")


# --- Errores 5: patrones de teclado, secuencia, repetición -----------------


def test_keyboard_walk_is_detected():
    result = analyzer.analyze("qwertyuiop")
    assert any(f["id"] == "keyboard" for f in result["findings"])


def test_sequence_is_detected():
    result = analyzer.analyze("abcdefgh")
    assert any(f["id"] == "sequence" for f in result["findings"])


def test_repeat_is_detected():
    result = analyzer.analyze("aaaaaaaa")
    assert any(f["id"] == "repeat" for f in result["findings"])


def test_reversed_sequence_is_detected():
    result = analyzer.analyze("9876543210")
    assert any(f["id"] == "sequence" for f in result["findings"])


# --- Contrato de la política ------------------------------------------------


def test_score_label_matches_scale():
    """La etiqueta del score sale de la escala, no de un diccionario aparte."""
    for password in ("123456", "aaaaaaaa", "xK9#mQ2$", "V*r!7zQ2#Lp@Wn4&bY8^"):
        result = analyzer.analyze(password)
        expected = policy.score_for_bits(result["entropy_bits"])
        assert result["score"] == expected["level"]
        assert result["score_label"] == expected["label"]
        assert result["score_color"] == expected["color"]


def test_score_thresholds_from_the_scale():
    assert policy.score_for_bits(0.0)["level"] == 0
    assert policy.score_for_bits(27.9)["level"] == 0
    assert policy.score_for_bits(28.0)["level"] == 1
    assert policy.score_for_bits(44.0)["level"] == 2
    assert policy.score_for_bits(60.0)["level"] == 3
    assert policy.score_for_bits(80.0)["level"] == 4


def test_entropy_is_monotonic_in_length():
    """Más caracteres nunca puede dar menos entropía en este modelo."""
    short = analyzer.analyze("xK9#mQ2$")
    long = analyzer.analyze("xK9#mQ2$extra")
    assert long["entropy_bits"] > short["entropy_bits"]


def test_empty_password_is_valid_dict():
    result = analyzer.analyze("")
    assert result["entropy_bits"] == 0
    assert not result["valid"]
    assert result["score"] == 0


def test_context_is_used():
    """Un término de contexto debe hacer más débil una contraseña.

    Solo cuenta si el término aparece DENTRO de la contraseña. `gmail.com` no
    está en "hola", así que no dispara nada; `julian` sí lo está en
    "julianpacheco".
    """
    result = analyzer.analyze("julianpacheco", context=["gmail.com", "julian"])
    assert any(f["id"] == "context" for f in result["findings"])


def test_context_absent_from_password_is_ignored():
    result = analyzer.analyze("hola", context=["gmail.com"])
    assert not any(f["id"] == "context" for f in result["findings"])


def test_context_short_terms_are_skipped():
    """Un contexto de menos de 3 caracteres generaría falsos positivos."""
    result = analyzer.analyze("hola", context=["a", "ab"])
    assert not any(f["id"] == "context" for f in result["findings"])


def test_crack_time_is_present_and_human():
    result = analyzer.analyze("V*r!7zQ2#Lp@Wn4&bY8^")
    assert result["crack_time"]["human"]
    assert result["crack_time"]["seconds"] > 0


def test_masking_never_returns_the_raw_password():
    """La respuesta pública no debe incluir la contraseña en claro."""
    password = "Sup3rS3cr3t!2024"
    result = analyzer.analyze(password)
    # Recorremos todos los valores de la respuesta buscando la contraseña.
    def contains(value):
        if isinstance(value, str):
            return password in value
        if isinstance(value, dict):
            return any(contains(v) for v in value.values())
        if isinstance(value, list):
            return any(contains(v) for v in value)
        return False

    assert not contains(result), "la contraseña aparece en claro en la respuesta"
