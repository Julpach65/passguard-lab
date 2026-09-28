"""El contrato entre `static/app.js` y la API, verificado con código.

El frontend y el backend se escribieron por separado, y un desajuste entre los
dos no aparece como error visible: la interfaz simplemente deja de pintar el
número y nadie sabe por qué. Estos tests leen el JavaScript real desde el disco,
y comprueban que cada campo que el cliente consume existe de verdad en la
respuesta del servidor.

Si alguien renombra una clave en `analyzer.py` y olvida `app.js`, falla aquí.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

import app as app_module
import policy

STATIC = Path(__file__).resolve().parent.parent / "static"
APP_JS = STATIC / "app.js"
CONFIG_JS = STATIC / "config.js"

# `result.algo` — el grupo incluye dígitos, porque `guesses_log10` es una clave
# válida y `guesses_log` no existe. Una expresión sin `\d` parte el nombre por
# la mitad y reporta un desajuste que no existe.
FIELD_ACCESS = re.compile(r"\b(?:result|currentResult|base|raw|entry|rule|policy)\.([A-Za-z_][A-Za-z0-9_]*)")
ENDPOINT_CALL = re.compile(r"request\(['\"](/api/[a-z]+)['\"]")

# El espejo de política vive en un literal JS. No se evalúa: se leen los
# literales con expresiones regulares, que es suficiente para comparar y no
# obliga a ejecutar el archivo en un entorno de Node.
RULE_LITERAL = re.compile(
    r"\{\s*id:\s*'([^']+)',\s*label:\s*'([^']*)',\s*"
    r"kind:\s*'([^']+)',\s*value:\s*([^,}]+?)\s*\}"
)
SCORE_LITERAL = re.compile(
    r"\{\s*level:\s*(\d+),\s*min_bits:\s*([\d.]+),\s*"
    r"label:\s*'([^']*)',\s*color:\s*'(#[0-9A-Fa-f]{6})'\s*\}"
)


def _strip_comments(source: str) -> str:
    """Quita comentarios de línea y de bloque.

    Necesario para buscar símbolos en el código y no en la prosa que lo
    rodea: un comentario que explica por qué se eliminó `pw_hmac` contiene la
    palabra, y un test que solo busca cadenas concluiría que el bug sigue vivo.
    """
    without_block = re.sub(r"/\*.*?\*/", " ", source, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", " ", without_block)


def _mirror_block(app_js: str) -> str:
    """El trozo de `app.js` que contiene el espejo de política."""
    start = app_js.index("FALLBACK_POLICY")
    end = app_js.index("fromServer:", start)
    return app_js[start:end]


def _client_rules(app_js: str) -> list[dict[str, object]]:
    rules = []
    for rule_id, label, kind, value in RULE_LITERAL.findall(_mirror_block(app_js)):
        raw_value = value.strip()
        try:
            parsed: object = int(raw_value)
        except ValueError:
            parsed = raw_value.strip("'\"")
        rules.append(
            {"id": rule_id, "label": label, "kind": kind, "value": parsed}
        )
    return rules


def _client_scores(app_js: str) -> list[dict[str, object]]:
    return [
        {"level": int(level), "min_bits": min_bits, "label": label, "color": color}
        for level, min_bits, label, color in SCORE_LITERAL.findall(_mirror_block(app_js))
    ]


def _assert_same_value(client_value: object, server_value: object, rule_id: str) -> None:
    """Compara valores sin confundir `40` con `40.0`.

    El espejo del cliente escribe enteros donde `policy.py` usa float, porque en
    JavaScript no hay diferencia. Comparar como cadena marcaría esa divergencia
    como un fallo cuando no lo es.
    """
    try:
        assert float(client_value) == float(server_value)
    except (TypeError, ValueError):
        assert str(client_value) == str(server_value), (
            f"valor divergente en la regla {rule_id!r}: "
            f"el cliente dice {client_value!r} y el servidor {server_value!r}"
        )


@pytest.fixture(scope="module")
def app_js() -> str:
    return APP_JS.read_text(encoding="utf-8")


# --- Los endpoints que el cliente llama existen en el servidor ----------------


def test_every_endpoint_in_the_client_exists_on_the_server(app_js):
    """Cada `/api/...` que pide el cliente tiene que existir en Flask."""
    called = set(ENDPOINT_CALL.findall(app_js))
    assert called, "no se encontró ningún endpoint en app.js"

    rules = {rule.rule for rule in app_module.app.url_map.iter_rules()}
    for endpoint in called:
        assert endpoint in rules, f"app.js llama a {endpoint} y Flask no lo sirve"


def test_client_sends_the_expected_client_header(app_js):
    """El header `X-Passguard-Client` es lo que exige el preflight."""
    assert "X-Passguard-Client" in app_js
    assert "X-Passguard-Client" in app_module.security_headers.CLIENT_HEADER


def test_client_reads_api_base_from_config(app_js):
    assert "PASSGUARD_CONFIG" in app_js
    assert "apiBase" in app_js


def test_config_js_declares_the_knobs():
    source = CONFIG_JS.read_text(encoding="utf-8")
    assert "PASSGUARD_CONFIG" in source
    assert "apiBase" in source
    # El typo `hibrEnabled` es historical; el cliente lo acepta, pero el
    # comentario del archivo debe seguir documentando la opción.
    assert "hibrEnabled" in source or "hibpEnabled" in source


# --- Los campos que el cliente consume existen en la respuesta --------------


def test_analyze_response_has_every_field_the_client_reads(client, app_js):
    response = client.post("/api/analyze", json={"password": "V*r!7zQ2#Lp@Wn4&bY8^"})
    assert response.status_code == 200
    body = response.get_json()

    # Subconjunto que la interfaz lee del resultado del análisis.
    consumed = {
        "password_length", "entropy_bits", "checks", "score", "score_color",
        "score_label", "charset_size", "guesses_log10", "crack_time", "valid",
        "source", "findings", "explanation",
    }
    missing = consumed - set(body)
    assert not missing, f"app.js lee campos que /api/analyze no devuelve: {sorted(missing)}"

    # Y que ninguna de esas claves quede con valor nulo cuando el cliente la
    # usa como número o cadena sin comprobar.
    for key in consumed:
        assert body[key] is not None, f"{key} llegó nulo y la interfaz lo usa directamente"


def test_analyze_findings_have_the_fields_the_client_renders(client):
    body = client.post("/api/analyze", json={"password": "qwertyuiop123"}).get_json()
    assert body["findings"], "el caso de prueba debe producir hallazgos"
    for finding in body["findings"]:
        # app.js pinta `label`, `detail`, `severity` y coloca `masked`.
        assert finding.get("label"), "cada hallazgo necesita una etiqueta legible"
        assert finding.get("severity") in {"critical", "high", "medium", "low"}
        assert "detail" in finding


def test_crack_time_has_the_subfields_the_client_formats(client, app_js):
    body = client.post("/api/analyze", json={"password": "abcabc12345"}).get_json()
    crack = body["crack_time"]
    # app.js lee crack_time.human y crack_time.attempts_per_second.
    assert isinstance(crack["human"], str) and crack["human"]
    assert crack["attempts_per_second"] > 0
    assert "crack_time" in app_js


def test_policy_response_matches_what_the_client_renders(client, app_js):
    body = client.get("/api/policy").get_json()
    # app.js recorre rules y usa rule.id, rule.label y rule.kind.
    assert body["rules"]
    for rule in body["rules"]:
        assert {"id", "label", "kind"} <= set(rule)
    # Y usa scores para pintar la escala.
    assert body["scores"]
    for entry in body["scores"]:
        assert {"level", "min_bits", "label"} <= set(entry)


def test_generate_response_has_every_field_the_client_reads(client):
    app_module.limiter.reset()
    body = client.post(
        "/api/generate", json={"length": 20, "alphabet": "web"}
    ).get_json()
    consumed = {
        "password", "length", "alphabet", "alphabet_size", "entropy_bits",
        "classes_present", "policy_satisfied", "analysis",
    }
    missing = consumed - set(body)
    assert not missing, f"app.js lee campos que /api/generate no devuelve: {sorted(missing)}"
    assert body["analysis"]["policy_id"] == policy.POLICY_ID


def test_health_response_shape(client):
    body = client.get("/api/health").get_json()
    # app.js decide si mostrar el indicador "servidor en línea" con esto.
    assert body["status"] == "ok"
    assert "service" in body


def test_audit_response_has_the_receipt_the_client_shows(client):
    body = client.post(
        "/api/audit", json={"password": "Auditable#2026"}
    ).get_json()
    assert "receipt" in body
    assert "audit_id" in body


def test_client_sends_the_password_the_server_actually_expects(app_js):
    """Lo que el navegador manda a /api/audit tiene que ser lo que el servidor lee.

    Este fallo existió: app.js calculaba un HMAC en el cliente y lo enviaba como
    `pw_hmac` junto a un score propio, mientras que /api/audit recalcula el
    análisis desde `password` e ignora todo lo demás. Con red, la auditoría
    respondía 400 "Falta 'password'". Los tests del servidor pasaban porque
    ellos sí mandaban `password`: el contrato comprobaba al servidor, nunca lo
    que el navegador envía.
    """
    code = _strip_comments(app_js)
    audit_call = re.search(
        r"api\.audit\(\{(?P<body>.*?)\}\)", code, re.DOTALL
    )
    assert audit_call, (
        "no se encuentra una llamada api.audit({ ... }) con el payload en línea. "
        "Se exige el literal en línea a propósito: si el payload se construye en "
        "una variable aparte, este test no puede leerlo y el contrato volvería a "
        "quedar sin comprobar, que es justo como pasó con este bug."
    )
    payload = audit_call.group("body")

    # El servidor exige 'password': es el único campo que hace falta.
    assert re.search(r"\bpassword\s*:", payload), (
        f"api.audit() no envía 'password'; el servidor responde 400. Payload: {payload.strip()}"
    )

    # Y no debe mandar campos que el servidor ignora: enviar un score propio
    # sugiere que el cliente participa en el veredicto, y no es así.
    for dead in ("pw_hmac", "score", "guesses_log10", "findings", "policy_id"):
        assert not re.search(rf"\b{dead}\s*:", payload), (
            f"api.audit() envía {dead!r}, que /api/audit ignora: el veredicto es "
            f"del servidor. Payload: {payload.strip()}"
        )


def test_client_never_computes_the_audit_hmac(app_js):
    """La clave del HMAC vive en el servidor y no sale de él.

    Un HMAC calculado en el navegador jamás podría compararse con el del
    servidor, así que mantener ese código era mantener una illusion.
    """
    for dead in ("hmacOf", "pw_hmac", "SESSION_KEY", "subtle.sign"):
        assert dead not in _strip_comments(app_js), (
            f"app.js todavía contiene {dead!r}: el HMAC de auditoría lo calcula "
            f"el servidor, no el cliente"
        )


def test_client_policy_mirror_matches_the_server(client, app_js):
    """app.js lleva un espejo de la política para el modo local.

    Si el espejo y el servidor discrepan, el usuario ve una cosa con red y otra
    sin ella, y no hay forma de saber cuál de las dos es la buena. Se comparan
    las reglas una a una: id, etiqueta, tipo y valor.
    """
    body = client.get("/api/policy").get_json()
    mirror = {rule["id"]: rule for rule in _client_rules(app_js)}

    assert set(mirror) == {rule["id"] for rule in body["rules"]}, (
        "las reglas del espejo de app.js no coinciden con las del servidor"
    )

    for server_rule in body["rules"]:
        client_rule = mirror[server_rule["id"]]
        assert client_rule["label"] == server_rule["label"], (
            f"etiqueta divergente en la regla {server_rule['id']!r}: "
            f"el cliente dice {client_rule['label']!r} y el servidor "
            f"{server_rule['label']!r}"
        )
        assert client_rule["kind"] == server_rule["kind"]
        if server_rule.get("value") is not None:
            _assert_same_value(client_rule["value"], server_rule["value"], server_rule["id"])


def test_client_score_scale_matches_the_server(client, app_js):
    """La escala 0-4 con sus umbrales y colores también está duplicada."""
    body = client.get("/api/policy").get_json()
    mirror = {entry["level"]: entry for entry in _client_scores(app_js)}

    assert set(mirror) == {entry["level"] for entry in body["scores"]}
    for server_entry in body["scores"]:
        client_entry = mirror[server_entry["level"]]
        assert client_entry["label"] == server_entry["label"]
        assert float(client_entry["min_bits"]) == float(server_entry["min_bits"])
        assert client_entry["color"].upper() == server_entry["color"].upper()


def test_client_policy_mirror_has_the_right_limits(app_js):
    """Las constantes numéricas del espejo, comparadas con policy.py."""
    for name, expected in (
        ("min_length", policy.MIN_LENGTH),
        ("max_length", policy.MAX_LENGTH),
        ("min_entropy_bits", int(policy.MIN_ENTROPY_BITS)),
    ):
        match = re.search(rf"{name}:\s*(\d+)", app_js)
        assert match, f"app.js no declara {name}"
        assert int(match.group(1)) == expected, (
            f"app.js dice {name}={match.group(1)} y policy.py dice {expected}"
        )


def test_error_shape_is_what_the_client_expects(client, app_js):
    """El cliente ramifica por `error.code`, así que la forma es obligatoria."""
    response = client.post("/api/analyze", json={"password": None})
    assert response.status_code == 400
    body = response.get_json()
    assert set(body) == {"error"}
    assert {"code", "message"} <= set(body["error"])
    assert "error.code" in app_js or "error" in app_js
