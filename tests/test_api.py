"""Pruebas de la API: contrato, códigos de error, CORS y límites.

Cada prueba de aquí fija un comportamiento que el frontend depende. Si cambias
una clave del JSON, esta suite es la que te avisa en lugar de descubrirlo en
producción.
"""

from __future__ import annotations

import dataclasses
import json

import pytest

import app as app_module
import policy
import security_headers
from config import config


@pytest.fixture
def client():
    app_module.limiter.reset()
    with app_module.app.test_client() as test_client:
        yield test_client
    app_module.limiter.reset()


# --- Rutas de lectura --------------------------------------------------------

def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.get_json()
    assert body["status"] == "ok"
    assert body["service"] == "passguard-api"
    assert body["policy_id"] == policy.POLICY_ID


def test_policy(client):
    response = client.get("/api/policy")
    assert response.status_code == 200
    body = response.get_json()
    # El frontend lee rules, scores y el id de política para pintar la tabla.
    assert body["policy_id"] == policy.POLICY_ID
    assert body["min_length"] == policy.MIN_LENGTH
    assert body["max_length"] == policy.MAX_LENGTH
    assert len(body["rules"]) == len(policy.RULES)
    assert len(body["scores"]) == len(policy.SCORE_SCALE)
    # El contrato real de una regla es id/label/kind/value. `app.js` usa
    # `rule.id` para el check y `rule.kind` para decidir si pinta el valor
    # numérico, así que los dos tienen que estar.
    for rule in body["rules"]:
        assert {"id", "label", "kind"} <= set(rule)


# --- analyze: contrato de respuesta ----------------------------------------


def test_analyze_returns_the_frontend_contract(client):
    response = client.post("/api/analyze", json={"password": "aA1!aA1!aA1!aA1!"})
    assert response.status_code == 200
    body = response.get_json()

    # Estas son las claves que app.js lee. Si falta una, la UI se rompe.
    required = {
        "valid", "score", "score_label", "score_color", "entropy_bits",
        "guesses_log10", "crack_time", "findings", "checks", "missing",
        "explanation", "policy_id", "policy_version", "source",
    }
    assert required <= set(body), f"faltan claves: {required - set(body)}"

    assert body["source"] == "server"
    assert body["crack_time"]["human"]
    assert body["crack_time"]["attempts_per_second"] == policy.ATTACKS_PER_SECOND
    for finding in body["findings"]:
        assert {"id", "severity", "label", "detail"} <= set(finding)
        assert finding["severity"] in {"critical", "high", "medium", "low"}


def test_analyze_accepts_context(client):
    response = client.post(
        "/api/analyze",
        json={"password": "julianpacheco", "context": ["julian", "gmail.com"]},
    )
    assert response.status_code == 200
    assert any(f["id"] == "context" for f in response.get_json()["findings"])


def test_analyze_never_echoes_the_password(client):
    """La respuesta no puede contener la contraseña en claro, en ninguna clave."""
    secret = "UnicaYToyNoDeberiaAparecer#2026"
    body = client.post("/api/analyze", json={"password": secret}).get_json()
    assert secret not in json.dumps(body, ensure_ascii=False)


# --- Errores: la versión anterior devolvía 500 o se colgaba -----------------


@pytest.mark.parametrize(
    "payload",
    [
        {"password": None},
        {"password": 123},
        {"password": 1.5},
        {"password": True},
        {"password": ["a"]},
        {"password": {"a": 1}},
        {},
    ],
)
def test_analyze_rejects_bad_types(client, payload):
    response = client.post("/api/analyze", json=payload)
    assert response.status_code in (200, 400)
    if response.status_code == 400:
        assert response.get_json()["error"]["code"] in {
            "invalid_request",
            "payload_too_large",
        }


def test_analyze_rejects_oversized_payload(client):
    response = client.post("/api/analyze", json={"password": "a" * 200_000})
    assert response.status_code == 413
    assert response.get_json()["error"]["code"] == "payload_too_large"


def test_analyze_survives_garbage_json(client):
    """La app original reventaba con 500 si el cuerpo no era JSON válido."""
    response = client.post(
        "/api/analyze", data="{no es json", content_type="application/json"
    )
    assert response.status_code == 400
    # El cuerpo se distinguishable del campo: `invalid_json` y no el genérico.
    assert response.get_json()["error"]["code"] == "invalid_json"


def test_analyze_survives_wrong_content_type(client):
    response = client.post("/api/analyze", data="password=abc", content_type="text/plain")
    assert response.status_code == 400


# --- generate: incluye el bug del bucle infinito ----------------------------


@pytest.mark.parametrize(
    "body",
    [
        {"length": 0},
        {"length": -5},
        {"length": 1.9},
        {"length": True},
        {"length": None},
        {"length": "abc"},
        {"length": 100_000},
        {"length": 5, "min_classes": 4, "groups": []},
    ],
)
def test_generate_rejects_bad_input(client, body):
    response = client.post("/api/generate", json=body)
    assert response.status_code in (200, 400)
    if response.status_code == 400:
        assert response.get_json()["error"]["code"] == "invalid_request"


def test_generate_clamps_short_length_without_hanging(client):
    """El `while True` original colgaba para siempre con longitudes menores a 12.

    Una longitud corta pero positiva se recorta a 12; un 0 o un negativo se
    rechaza con 400. Lo importante es que ninguna de las dos sale con 500 ni
    tarda: el bucle infinito ya no existe.
    """
    for requested in (1, 5, 11, 12):
        app_module.limiter.reset()
        response = client.post("/api/generate", json={"length": requested})
        assert response.status_code == 200
        assert response.get_json()["length"] >= policy.MIN_LENGTH

    for requested in (0, -1, -500):
        app_module.limiter.reset()
        response = client.post("/api/generate", json={"length": requested})
        assert response.status_code == 400


def test_generate_rejects_length_far_over_the_maximum(client):
    """Muy por encima del tope es un 400, no un recorte silencioso.

    El recorte se reserva para lo que está cerca del rango válido; un 10000 es
    un error del cliente y ocultarlo con un 128 sería engañoso.
    """
    app_module.limiter.reset()
    response = client.post("/api/generate", json={"length": 10_000})
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "invalid_request"


def test_generate_caps_length_near_the_maximum(client):
    """Dentro del rango wide (hasta MAX_LENGTH*4) sí se recorta al máximo."""
    app_module.limiter.reset()
    body = client.post("/api/generate", json={"length": 300}).get_json()
    assert body["length"] == policy.MAX_LENGTH


def test_generate_meets_the_policy(client):
    app_module.limiter.reset()
    body = client.post(
        "/api/generate", json={"length": 20, "alphabet": "web", "avoid_ambiguous": True}
    ).get_json()
    assert body["policy_satisfied"] is True
    assert body["classes_present"] == 4
    assert body["length"] == 20
    assert body["attempts"] >= 1
    assert body["warnings"] == []


def test_generate_entropy_is_not_undercounted(client):
    """`alphabet_size` es el pozo del generador, no los caracteres observados.

    Confundir las dos cosas daba 3 bits para una contraseña de 20 caracteres.
    """
    app_module.limiter.reset()
    body = client.post("/api/generate", json={"length": 20, "alphabet": "web"}).get_json()
    assert body["alphabet_size"] > 20
    assert body["entropy_bits"] > 20 * 3


def test_generate_is_unique_across_calls(client):
    generated = set()
    for _ in range(10):
        app_module.limiter.reset()
        generated.add(client.post("/api/generate", json={"length": 16}).get_json()["password"])
    assert len(generated) == 10


def test_generate_rejects_unknown_alphabet(client):
    response = client.post("/api/generate", json={"alphabet": "hackeado"})
    assert response.status_code == 400


def test_generate_survives_many_sequential_calls(client):
    """200 generaciones seguidas: el rate limiter es lo único que puede cortar."""
    accepted = 0
    limited = 0
    for _ in range(200):
        app_module.limiter.reset()
        response = client.post("/api/generate", json={"length": 16})
        if response.status_code == 200:
            accepted += 1
        elif response.status_code == 429:
            limited += 1
        else:
            pytest.fail(f"código inesperado: {response.status_code}")
    assert accepted == 200
    assert limited == 0


# --- CORS: nunca comodín ----------------------------------------------------


def test_cors_never_returns_wildcard(client):
    for origin in (
        "https://julpach65.github.io",
        "https://evil.example.com",
        "http://localhost:8000",
    ):
        response = client.get("/api/health", headers={"Origin": origin})
        allowed = response.headers.get("Access-Control-Allow-Origin")
        assert allowed != "*"
        if origin in config.allowed_origins:
            assert allowed == origin
        else:
            assert allowed is None


def test_cors_allows_preflight_only_for_allowed_origins(client):
    """El preflight solo se autoriza para orígenes de la lista blanca.

    `https://julpach65.github.io` es el origen de producción, pero no está en la
    lista por defecto (que es local). Se prueba con un origen permitido de
    verdad, y luego se comprueba que el de GitHub NO se autoriza mientras no se
    configure: el fallo es cerrado.
    """
    allowed = config.allowed_origins[0]

    response = client.options(
        "/api/analyze",
        headers={
            "Origin": allowed,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-passguard-client",
        },
    )
    assert response.status_code in (200, 204)
    assert response.headers.get("Access-Control-Allow-Origin") == allowed
    assert "POST" in response.headers.get("Access-Control-Allow-Methods", "")
    assert "X-Passguard-Client" in response.headers.get("Access-Control-Allow-Headers", "")

    rejected = client.options(
        "/api/analyze",
        headers={
            "Origin": "https://julpach65.github.io",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert rejected.headers.get("Access-Control-Allow-Origin") is None


def test_cors_authorized_when_origin_is_configured(client, monkeypatch):
    """Con el origen en la lista, el navegador puede leer la respuesta.

    `Config` es un dataclass frozen a propósito: la configuración no se puede
    mutar en caliente. Para probarlo se reconstruye con `dataclasses.replace`.

    El parche va sobre el módulo que CONSULTA la configuración
    (`security_headers`), no sobre `app`: cada módulo hace `from config import
    config` y guarda su propia referencia al objeto, así que sustituir la
    variable en uno no llega al otro. Es una limitación real del patrón, no un
    defecto de la prueba.
    """
    monkeypatch.setattr(
        security_headers,
        "config",
        dataclasses.replace(config, allowed_origins=("https://julpach65.github.io",)),
    )
    response = client.get(
        "/api/health", headers={"Origin": "https://julpach65.github.io"}
    )
    assert response.headers.get("Access-Control-Allow-Origin") == "https://julpach65.github.io"


def test_cors_does_not_leak_headers_to_unknown_origin(client):
    """Un origen que no está en la lista blanca recibe un 403, no un 200 mudo.

    Antes bastaba con no devolver `Access-Control-Allow-Origin`, lo que impedía
    leer la respuesta pero dejaba ejecutar la petición. `security_headers.guard`
    convierte el fallo en cerrado de verdad.
    """
    response = client.get("/api/health", headers={"Origin": "https://evil.example.com"})
    assert response.headers.get("Access-Control-Allow-Origin") is None
    assert response.status_code == 403
    assert response.get_json()["error"]["code"] == "origin_not_allowed"


def test_guard_rejects_preflight_from_unknown_origin(client):
    response = client.options(
        "/api/analyze",
        headers={
            "Origin": "https://evil.example.com",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert response.status_code == 403
    assert response.get_json()["error"]["code"] == "origin_not_allowed"


def test_guard_requires_client_header_on_cross_origin_writes(client):
    """Origen permitido no basta: la escritura también declara la cabecera.

    Es la misma condición que el preflight declara, comprobada en el servidor.
    """
    origin = config.allowed_origins[0]
    body = {"password": "P4$$w0rd!2026"}

    without_header = client.post("/api/analyze", json=body, headers={"Origin": origin})
    assert without_header.status_code == 403
    assert without_header.get_json()["error"]["code"] == "client_header_required"

    with_header = client.post(
        "/api/analyze",
        json=body,
        headers={"Origin": origin, security_headers.CLIENT_HEADER: "1"},
    )
    assert with_header.status_code == 200


def test_guard_allows_requests_without_origin(client):
    """Sin `Origin` no hay navegador entre sitios delante, así que se permite.

    Es el caso de curl, del comprobador de salud de PythonAnywhere y de estas
    propias pruebas; bloquearlo rompería el despliegue sin ganar seguridad.
    """
    assert client.get("/api/health").status_code == 200
    assert client.post("/api/analyze", json={"password": "P4$$w0rd!2026"}).status_code == 200


def test_security_headers_present(client):
    response = client.get("/api/health")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("Referrer-Policy")
    assert "Content-Security-Policy" in response.headers


# --- audit: nunca guarda la contraseña -------------------------------------


def test_audit_accepts_analysis_and_never_stores_password(client):
    response = client.post(
        "/api/audit",
        json={
            "policy_id": policy.POLICY_ID,
            "score": 3,
            "entropy_bits": 71.2,
            "findings": ["dict"],
            "password": "SecretoQueNoSeGuarda#2026",
        },
    )
    assert response.status_code == 200
    body = response.get_json()
    assert "receipt" in body
    # La respuesta no puede devolver la contraseña ni su hash sin sal.
    assert "SecretoQueNoSeGuarda#2026" not in json.dumps(body, ensure_ascii=False)


def test_audit_rejects_bad_payload(client):
    response = client.post("/api/audit", json={"nada": 1})
    assert response.status_code == 400


# --- hibp: degrada sin romper ----------------------------------------------


def test_hibp_rejects_bad_prefix(client):
    """Un prefijo de SHA-1 son 5 hex; cualquier otra cosa es un 400."""
    for bad in ("", "zzzzz", "1234", "ABCDEFXYZ"):
        response = client.post("/api/hibp", json={"prefix": bad})
        assert response.status_code in (200, 400, 503)
        if response.status_code == 400:
            assert response.get_json()["error"]["code"] == "invalid_request"


# --- errores genéricos en JSON, nunca HTML con traza ------------------------


def test_unknown_route_returns_json_error(client):
    """Cualquier ruta bajo /api responde JSON, sea 404 o 405.

    El 405 aparece porque la ruta comodín `OPTIONS /api/<path:any>` captura el
    prefijo y Flask ve que existe con otro método. El detalle importante es que
    la respuesta es JSON con la forma de error, no la página HTML por defecto.
    """
    response = client.get("/api/no-existe")
    assert response.status_code in (404, 405)
    assert response.is_json
    body = response.get_json()
    assert body["error"]["code"]
    assert body["error"]["message"]


def test_method_not_allowed_returns_json(client):
    response = client.put("/api/analyze")
    assert response.status_code == 405
    assert response.is_json
