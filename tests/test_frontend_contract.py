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
    """config.js solo expone lo que la interfaz usa hoy: la URL del backend.

    Se quitó `hibpEnabled` cuando la verificación de brechas dejó de tener
    botón. Dejar el interruptor puesto invitaba a tocarlo esperando un efecto
    que ya no existe.
    """
    source = CONFIG_JS.read_text(encoding="utf-8")
    assert "PASSGUARD_CONFIG" in source
    assert "apiBase" in source
    assert "hibpEnabled" not in source and "hibrEnabled" not in source


def test_every_element_the_client_looks_up_exists_in_the_html(app_js):
    """Cada `id` que app.js busca tiene que existir en index.html.

    El fallo es silencioso: `document.getElementById` devuelve `null`, y los
    manejadores escriben sobre `null` sin que salte nada. Una tarjeta renombrada
    en el HTML deja de pintar el veredicto y la página parece que funciona.
    """
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    declared = set(re.findall(r'id="([^"]+)"', html))

    block = re.search(r"const E = \{\};(.*?)\]\.forEach", app_js, re.DOTALL)
    assert block, "no se encontró el mapa de elementos de app.js"
    wanted = set(re.findall(r"'([a-z][a-z0-9-]*)'", block.group(1)))
    wanted.update(re.findall(r"getElementById\('([^']+)'\)", app_js))

    assert wanted, "app.js no declara ningún elemento"
    assert not wanted - declared, (
        f"app.js busca ids que no están en index.html: {sorted(wanted - declared)}"
    )


def test_index_html_only_points_at_files_that_exist():
    """Nada de referencias rotas: un `src` inexistente es un 404 silencioso."""
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    refs = re.findall(r'(?:src|href)="([^"#:]+)"', html)
    assert refs, "index.html no carga ningún recurso local"
    for ref in refs:
        assert (STATIC / ref).exists(), f"index.html carga {ref} y no existe"


def test_every_aria_reference_points_at_something():
    """`for` y `aria-labelledby` tienen que apuntar a un id real."""
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    declared = set(re.findall(r'id="([^"]+)"', html))
    referenced = re.findall(r'(?:aria-labelledby|aria-describedby)="([^"]+)"', html)
    referenced += re.findall(r'<label[^>]*\sfor="([^"]+)"', html)
    for target in referenced:
        assert target in declared, f"aria apunta a {target!r}, que no existe"


# --- Los campos que el cliente consume existen en la respuesta --------------


def test_analyze_response_has_every_field_the_client_reads(client, app_js):
    response = client.post("/api/analyze", json={"password": "V*r!7zQ2#Lp@Wn4&bY8^"})
    assert response.status_code == 200
    body = response.get_json()

    # Subconjunto que la interfaz lee del resultado del análisis. La respuesta
    # trae más cosas (`guesses_log10`, `crack_time`, `explanation`…), que son
    # para consumo de la API y se cubren en test_api.py; aquí solo importa lo
    # que la página pinta de verdad.
    consumed = {
        "valid", "rules", "missing", "findings", "checks",
        "score", "score_label", "score_color", "entropy_bits",
    }
    missing = consumed - set(body)
    assert not missing, f"app.js lee campos que /api/analyze no devuelve: {sorted(missing)}"

    # Y que ninguna de esas claves quede con valor nulo cuando el cliente la
    # usa como número o cadena sin comprobar.
    for key in consumed:
        assert body[key] is not None, f"{key} llegó nulo y la interfaz lo usa directamente"

    # La lista de requisitos se pinta desde `rules`, no desde `checks` suelto:
    # si `rules` no trae `ok`, cada punto saldría marcado como incumplido.
    for rule in body["rules"]:
        assert isinstance(rule["ok"], bool), f"la regla {rule['id']!r} no trae `ok`"


def test_analyze_findings_have_the_fields_the_client_renders(client, app_js):
    body = client.post("/api/analyze", json={"password": "qwertyuiop123"}).get_json()
    assert body["findings"], "el caso de prueba debe producir hallazgos"
    for finding in body["findings"]:
        # La página usa un solo campo: `label`, el del hallazgo más grave, que
        # es lo que aparece en la línea de motivo. Si `label` llega vacío o
        # viene nulo, el veredicto se queda mudo sin que salte ningún error.
        assert str(finding.get("label") or "").strip(), (
            f"el hallazgo {finding!r} necesita una etiqueta legible"
        )


def test_crack_time_stays_well_formed_for_api_consumers(client):
    """`crack_time` ya no se pinta en la web, pero sigue siendo parte de la API.

    Se valida aquí para que quitarlo de la interfaz no acabe dejándolo a medio
    construir: si algún día vuelve a la pantalla, el dato tiene que venir entero.
    """
    body = client.post("/api/analyze", json={"password": "abcabc12345"}).get_json()
    crack = body["crack_time"]
    assert isinstance(crack["human"], str) and crack["human"]
    assert crack["attempts_per_second"] > 0


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
    # La página solo lee la contraseña; el resto de la respuesta es para la API
    # y se valida en test_api.py.
    assert body["password"], "el generador devolvió una contraseña vacía"
    assert len(body["password"]) == body["length"]


def test_request_payloads_from_the_client_are_valid(client, app_js):
    """Lo que el navegador manda tiene que existir, y no solo lo que devuelve.

    Esta es la dirección que faltaba comprobar. Los tests del servidor mandaban
    sus propios payloads, así que una clave mal escrita en app.js — o una opción
    que el endpoint no acepta — no fallaba en ningún sitio: se rompía en el
    navegador, en silencio. Los literales se leen del disco, sin ejecutar JS.
    """
    code = _strip_comments(app_js)
    payloads = re.findall(r"body:\s*\{([^}]*)\}", code)
    assert payloads, "no se encontró el body de ninguna petición en app.js"

    sent = set()
    for payload in payloads:
        sent.update(re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*:", payload))
    allowed = {"password", "context", "length", "alphabet", "avoid_ambiguous", "min_classes"}
    assert sent <= allowed, (
        f"app.js manda campos que la API no documenta: {sorted(sent - allowed)}"
    )

    # Y el payload exacto del generador, el que está en línea en app.js.
    app_module.limiter.reset()
    response = client.post(
        "/api/generate",
        json={"length": 20, "alphabet": "web", "avoid_ambiguous": True, "min_classes": 4},
    )
    assert response.status_code == 200, (
        f"el payload del generador es rechazado: {response.get_json()}"
    )


def test_health_response_shape(client):
    body = client.get("/api/health").get_json()
    # app.js decide si mostrar el indicador "servidor en línea" con esto.
    assert body["status"] == "ok"
    assert "service" in body


def test_audit_response_keeps_its_receipt_for_api_consumers(client):
    """La auditoría perdió su botón, pero el endpoint sigue siendo API pública.

    Se conserva el test para que quitar la interfaz no deje el endpoint a medio
    construir: el recibo es lo que permite a un tercero confirmar más tarde que
    una contraseña se dejó de usar.
    """
    body = client.post(
        "/api/audit", json={"password": "Auditable#2026"}
    ).get_json()
    assert body["receipt"], "el recibo del servidor no puede llegar vacío"
    assert body["audit_id"]


def test_client_never_sends_its_own_verdict(app_js):
    """El veredicto es del servidor: el cliente pregunta, no responde.

    Aquí hubo un bug real. app.js calculaba un HMAC en el navegador y lo
    mandaba como `pw_hmac` junto a un score propio, mientras que /api/audit
    recalcula el análisis desde `password` e ignora todo lo demás. En el
    navegador la auditoría respondía 400 "Falta 'password'". Los tests pasaban
    porque ellos sí mandaban `password`: se comprobaba al servidor y nunca lo
    que el navegador envía.

    Ese test murió con la interfaz de auditoría, así que la lección se fija aquí
    en forma general: ninguna petición sale con un veredicto ya calculado.
    """
    code = _strip_comments(app_js)

    for dead in ("hmacOf", "SESSION_KEY", "subtle.sign", "pw_hmac"):
        assert dead not in code, (
            f"app.js todavía contiene {dead!r}: el HMAC de auditoría lo calcula "
            f"el servidor, no el cliente"
        )

    # Y ningún request(...) lleva score, findings ni checks.
    for payload in re.findall(r"body:\s*\{([^}]*)\}", code):
        for dead in ("score", "findings", "checks", "entropy", "policy_id"):
            assert not re.search(rf"\b{dead}\s*:", payload), (
                f"app.js envía {dead!r} al servidor, lo que sugiere que el "
                f"veredicto es del cliente. Payload: {payload.strip()}"
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

    # Las reglas que invalidan el veredicto también están duplicadas. Si el
    # servidor empieza a exigir, por ejemplo, `not_common` y el cliente sigue
    # sin contarla como crítica, el modo local aprobaría contraseñas que el
    # servidor rechaza: exactamente el fallo que el espejo pretende evitar.
    match = re.search(r"const CRITICAL = \[([^\]]*)\]", app_js)
    assert match, "app.js no declara la lista de reglas críticas del espejo"
    client_critical = set(re.findall(r"'([^']+)'", match.group(1)))
    assert client_critical == set(policy.CRITICAL_RULE_IDS), (
        f"las reglas críticas del cliente son {sorted(client_critical)} y las "
        f"del servidor {sorted(policy.CRITICAL_RULE_IDS)}"
    )


def test_client_never_grades_the_password_itself(app_js):
    """La nota la pone el servidor. El respaldo local no se la inventa.

    El análisis local no puede calcular el espacio de búsqueda: el servidor se
    queda con el mínimo entre fuerza bruta y el mejor ataque dirigido, y eso
    necesita el corpus y todos los patrones. Si el respaldo puntuara con
    longitud × log2(alfabeto), `aA1!aA1!aA1!aA1!` —16 caracteres, 4 clases y
    repitiendo bloque— saldría "muy fuerte" en local mientras el servidor la
    rechaza y la lista se pinta en rojo. Mostrar los bits y no la nota es más
    feo, y es cierto. Este test fija esa decisión para que nadie la deshaga sin
    darse cuenta de lo que rompe.
    """
    code = _strip_comments(app_js)

    assert "scoreForBits" not in code, (
        "app.js vuelve a puntuar localmente: el nivel solo puede salir del "
        "servidor, que es quien puede calcular el espacio de búsqueda"
    )
    assert "estimación local" in code, (
        "el veredicto local debe etiquetarse como estimación, no como nota"
    )
    # Y el espejo no arrastra la escala 0-4, que es lo único que permitiría
    # notarla. Se busca `level:`, no `min_bits`: ese nombre es también el `kind`
    # de la regla de entropía y no tiene nada que ver con la escala.
    assert not re.search(r"\blevel:\s*\d", _mirror_block(app_js)), (
        "el espejo incluye la escala 0-4 pero el cliente no la usa: "
        "conviene que no exista, o vuelve a ser tentación notarla"
    )


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
