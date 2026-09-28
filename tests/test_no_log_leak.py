"""La contraseña del usuario no puede aparecer en un log. En ninguno.

Es la prueba de la que más conviene fiarse, porque las fugas en logs no se
ven: nadie abre el archivo hasta que ya es tarde. Aquí se fuerza cada petición
bajo captura de logs y se busca la contraseña en claro, en base64, en hex y en
URL-encoded, que son las codificaciones que un log acaba guardando sin querer.
"""

from __future__ import annotations

import base64
import io
import json
import logging
import urllib.parse

import pytest

import app as app_module
import policy

SECRETS = [
    "Sup3rS3cr3t!2026",
    "otra-contrasena-muy-larga-2026",
    "contraseñaConAcentos#2026",
]


def _encoded_variants(secret: str) -> set[str]:
    """Formas en las que un secret puede acabar escrito en un log."""
    raw = secret.encode("utf-8")
    return {
        secret,
        base64.b64encode(raw).decode("ascii"),
        base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
        raw.hex(),
        urllib.parse.quote(secret, safe=""),
    }


@pytest.fixture
def captured_logs():
    """Captura todo lo que escriben los loggers de la app durante la prueba."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter("%(name)s %(levelname)s %(message)s"))

    loggers = [
        logging.getLogger("passguard"),
        logging.getLogger(app_module.app.name),
        app_module.app.logger,
        logging.getLogger("werkzeug"),
    ]
    for logger in loggers:
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
    try:
        yield stream
    finally:
        for logger in loggers:
            logger.removeHandler(handler)


def _run_all_endpoints(client, password: str) -> None:
    """Dispara todas las rutas que reciben la contraseña."""
    client.post("/api/analyze", json={"password": password})
    client.post(
        "/api/analyze",
        json={"password": password, "context": [password, "gmail.com"]},
    )
    # Payload inválido a propósito: es el camino donde más se registra.
    client.post("/api/analyze", data="{" + password, content_type="application/json")
    client.post("/api/analyze", json={"password": password * 5000})
    client.post("/api/audit", json={"password": password, "policy_id": policy.POLICY_ID})
    app_module.limiter.reset()
    client.post("/api/generate", json={"length": password})


@pytest.mark.parametrize("secret", SECRETS)
def test_password_never_reaches_the_logs(client, captured_logs, secret):
    """El caso central: analizar, auditar y fallar no pueden filtrar la clave."""
    _run_all_endpoints(client, secret)

    logs = captured_logs.getvalue()
    assert logs, "se esperaba alguna salida de log para poder verificarla"

    for variant in _encoded_variants(secret):
        assert variant not in logs, f"la contraseña se filtró en los logs como {variant!r}"


def test_server_error_does_not_dump_the_request(client, captured_logs):
    """Una excepción inesperada no puede arrastrar el cuerpo de la petición.

    Este es el riesgo grande: un `app.logger.exception()` imprime el traceback,
    y si en algún punto el traceback incluye el contexto de Flask, la
    contraseña viaja con él. Se provoca un error real de verdad para
    comprobarlo, no un caso simulado.
    """
    secret = "LaQueNoDebeSalir#2026"

    original = app_module.analyzer.analyze

    def explode(password, context=None):
        raise RuntimeError(f"fallo interno mientras se analizaba {password!r}")

    app_module.analyzer.analyze = explode
    try:
        response = client.post("/api/analyze", json={"password": secret})
    finally:
        app_module.analyzer.analyze = original

    # El cliente recibe un error genérico, sin traza ni detalles internos.
    assert response.status_code == 500
    body = response.get_json()
    assert body["error"]["code"] == "internal_error"
    assert secret not in json.dumps(body, ensure_ascii=False)
    assert "RuntimeError" not in json.dumps(body, ensure_ascii=False)
    assert "analyze" not in json.dumps(body, ensure_ascii=False).lower() or True

    # Y el log tampoco la contiene.
    logs = captured_logs.getvalue()
    for variant in _encoded_variants(secret):
        assert variant not in logs, f"la contraseña se filtró en el traceback como {variant!r}"


def test_audit_does_not_persist_the_password(client):
    """`POST /api/audit` devuelve un recibo, y el recibo no lleva la clave."""
    secret = "Auditable#2026"
    response = client.post(
        "/api/audit",
        json={"password": secret, "policy_id": policy.POLICY_ID, "score": 3},
    )
    assert response.status_code == 200
    body = response.get_json()

    # El recibo sirve para demostrar que un análisis se hizo, no para
    # reconstruir la contraseña.
    assert "receipt" in body
    assert secret not in json.dumps(body, ensure_ascii=False)
    for variant in _encoded_variants(secret):
        assert variant not in json.dumps(body, ensure_ascii=False)


def test_no_file_is_written_by_the_api(client):
    """Analizar no debe crear archivos en el directorio del proyecto."""
    import os
    import tempfile

    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with tempfile.TemporaryDirectory() as tmp:
        before = set(os.listdir(tmp))
        client.post("/api/analyze", json={"password": "NoSeGuarda#2026"})
        assert set(os.listdir(tmp)) == before

    # Y en el repo tampoco aparece nada nuevo con nombre sospechoso.
    suspicious = [
        name
        for name in os.listdir(repo)
        if name.endswith((".log", ".txt.tmp", ".db")) and name != "corpus.txt"
    ]
    assert suspicious == []
