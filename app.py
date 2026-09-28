"""PassGuard Lab - API de análisis de contraseñas.

Arquitectura deliberada en dos capas. El frontend vive en GitHub Pages y este
backend es la autoridad: el cliente decide latencia, el servidor decide
verdicto. El cliente puede mentir sobre la política; el servidor no.

Tres correcciones de seguridad respecto a la versión anterior de este proyecto,
que eran el problema más grave que tenía:

1. `debug=True` con `host='0.0.0.0'` exponía el debugger interactivo de
   Werkzeug a toda la red local. Con `TRUSTED_HOSTS` sin configurar, la página
   de traza servía el código fuente sin autenticar, y el PIN de la consola se
   deriva de la MAC del servidor. Ahora DEBUG sale del entorno, el host por
   defecto es 127.0.0.1, y en producción se sirve con gunicorn.

2. El generador original tenía un `while True` cuyo predicado exigía 12
   caracteres que él mismo no producía cuando la longitud pedida era menor. Con
   `{"length": 5}` el hilo se quedaba al 100% de CPU para siempre. Ahora la
   longitud se recorta al rango válido antes de generar y la garantía se
   construye sin rechazo.

3. No había validación de esquema: `{"password": null}` producía un TypeError
   y un HTTP 500 con traza HTML. Aquí todo esquema inválido es un 400 con JSON.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from typing import Any

from flask import Flask, jsonify, request, send_from_directory

import analyzer
import audit
import corpus
import generator
import policy
import ratelimit
import redact
import security_headers
from config import config
from errors import ApiError, register_error_handlers

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = config.max_content_length
app.config["JSON_SORT_KEYS"] = False

# Techo de reintentos del generador. Acotado a propósito: una combinación
# pedida que nunca puede cumplir la política debe agotar el presupuesto y
# devolver el mejor intento con una advertencia, no colgarse.
GENERATE_ATTEMPTS = 12

limiter = ratelimit.RateLimiter(config.rate_limit_window)
limiter.register("analyze", config.rate_limit_analyze)
limiter.register("generate", config.rate_limit_generate)
limiter.register("audit", config.rate_limit_audit)

register_error_handlers(app)
security_headers.register(app)


def _sweeper() -> None:
    """Poda periódica de las claves inactivas del limitador."""
    while True:
        time.sleep(300)
        try:
            limiter.sweep()
        except Exception:  # noqa: BLE001
            pass


threading.Thread(target=_sweeper, name="rate-sweeper", daemon=True).start()


# --------------------------------------------------------------------------- #
# validación de entrada
# --------------------------------------------------------------------------- #

def _body() -> dict:
    """Extrae y valida el cuerpo como objeto JSON.

    `get_json(silent=True)` devuelve None tanto para JSON inválido como para un
    content-type equivocado, así que se distinguen los dos casos para dar un
    mensaje útil.
    """
    if request.get_json(silent=True) is None:
        if not request.data:
            raise ApiError("invalid_json", "Falta el cuerpo de la petición.", 400)
        raise ApiError("invalid_json", "El cuerpo debe ser JSON válido.", 400)
    data = request.get_json(force=True, silent=True)
    if not isinstance(data, dict):
        raise ApiError("invalid_request", "El cuerpo debe ser un objeto JSON.", 400)
    return data


def _password(data: dict) -> str:
    """Extrae la contraseña validando el tipo.

    El `data.get('password', '')` original no protegía nada: si la clave existe
    con valor None, el default no se aplica y `len(None)` revienta.
    """
    if "password" not in data:
        return ""
    value = data["password"]
    if value is None:
        raise ApiError(
            "invalid_request",
            "El campo 'password' no puede ser null; envíalo como cadena de texto.",
            400,
        )
    if not isinstance(value, str):
        raise ApiError(
            "invalid_request",
            "El campo 'password' debe ser texto; se recibió otro tipo de dato.",
            400,
        )
    if len(value) > policy.MAX_LENGTH * 4:
        raise ApiError(
            "invalid_request",
            f"La contraseña excede el máximo admitido de {policy.MAX_LENGTH * 4} caracteres.",
            400,
        )
    return value


def _context(data: dict) -> list[str]:
    raw = data.get("context")
    if raw is None:
        return []
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise ApiError("invalid_request", "El campo 'context' debe ser una lista de texto.", 400)
    return [item for item in raw if item.strip()][:10]


def _int_field(data: dict, name: str, default: int, low: int, high: int) -> int:
    if name not in data:
        return default
    value = data[name]
    if value is None:
        raise ApiError(
            "invalid_request",
            f"El campo '{name}' no puede ser null; omítelo para usar el valor por defecto.",
            400,
        )
    # bool es subclase de int en Python: True llegaría como 1 sin este chequeo.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ApiError("invalid_request", f"El campo '{name}' debe ser un número entero.", 400)
    if not low <= value <= high:
        raise ApiError(
            "invalid_request",
            f"El campo '{name}' debe estar entre {low} y {high}.",
            400,
        )
    return value


def _guard(bucket: str) -> None:
    key = ratelimit.client_key(
        request.headers.get("X-Forwarded-For"), request.remote_addr
    )
    allowed, retry_after = limiter.check(bucket, key)
    if not allowed:
        raise ApiError(
            "rate_limited",
            "Demasiadas peticiones seguidas. Espera un momento.",
            429,
            {"Retry-After": str(retry_after)},
        )


# --------------------------------------------------------------------------- #
# rutas
# --------------------------------------------------------------------------- #

@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/api/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "service": config.service,
            "version": config.version,
            "policy_id": policy.POLICY_ID,
        }
    )


@app.get("/api/policy")
def get_policy():
    return jsonify(policy.as_dict(corpus.metadata(config.corpus_path)))


@app.post("/api/analyze")
def post_analyze():
    _guard("analyze")
    data = _body()
    password = _password(data)
    # Desde aquí hasta el final de la petición, cualquier texto que se escriba
    # al log lleva esta contraseña redactada.
    redact.register(password)
    result = analyzer.analyze(password, _context(data))
    audit.record(
        {
            "event": "analyze",
            "policy_id": result["policy_id"],
            "score": result["score"],
            "guesses_log10": result["guesses_log10"],
            "findings": sorted({f["id"] for f in result["findings"]}),
            "length": result["password_length"],
        }
    )
    return jsonify(result)


@app.post("/api/generate")
def post_generate():
    _guard("generate")
    data = _body()

    length = _int_field(data, "length", 20, 1, policy.MAX_LENGTH * 4)
    min_classes = _int_field(data, "min_classes", 3, 1, 4)
    avoid_ambiguous = data.get("avoid_ambiguous", True)
    if not isinstance(avoid_ambiguous, bool):
        raise ApiError("invalid_request", "El campo 'avoid_ambiguous' debe ser booleano.", 400)

    alphabet_name = data.get("alphabet", "web")
    if not isinstance(alphabet_name, str) or alphabet_name not in generator.ALPHABETS:
        raise ApiError(
            "invalid_request",
            "El campo 'alphabet' debe ser uno de: " + ", ".join(sorted(generator.ALPHABETS)) + ".",
            400,
        )

    groups = data.get("groups")
    if groups is None:
        groups = ["lowercase", "uppercase", "number", "symbol"]
    if not isinstance(groups, list) or not all(isinstance(g, str) for g in groups):
        raise ApiError("invalid_request", "El campo 'groups' debe ser una lista de texto.", 400)
    if not groups:
        raise ApiError("invalid_request", "Debe haber al menos una clase de caracteres activa.", 400)

    # El generador garantiza longitud y clases POR CONSTRUCCIÓN, pero no puede
    # saber si el resultado cae por azar sobre un patrón débil (contiene "abc",
    # un año, una palabra del diccionario...). Así que se reintenta con un
    # techo acotado. El techo importa: sin él, una petición con alfabeto
    # restringido que nunca puede satisfacer la política entraría en bucle.
    password = ""
    analysis: dict[str, Any] = {}
    attempts_used = 0
    for attempts_used in range(1, GENERATE_ATTEMPTS + 1):
        try:
            password = generator.generate(
                length=length,
                groups=groups,
                avoid_ambiguous=avoid_ambiguous,
                min_classes=min_classes,
                alphabet_name=alphabet_name,
            )
        except generator.GenerationError as exc:
            raise ApiError("invalid_request", str(exc), 400) from exc
        analysis = analyzer.analyze(password)
        if analysis["valid"]:
            break

    described = generator.describe(
        password, alphabet_name=alphabet_name, avoid_ambiguous=avoid_ambiguous
    )

    warnings: list[str] = []
    if not analysis.get("valid"):
        warnings.append(
            f"No se logró una contraseña que cumpla la política en {GENERATE_ATTEMPTS} "
            "intentos con los parámetros pedidos. Revisa el alfabeto o las clases."
        )

    return jsonify(
        {
            "password": password,
            "length": described["length"],
            "alphabet": alphabet_name,
            "alphabet_size": described["alphabet_size"],
            "entropy_bits": described["entropy_bits"],
            "classes_present": described["classes_present"],
            "policy_satisfied": bool(analysis.get("valid")),
            "attempts": attempts_used,
            "warnings": warnings,
            "analysis": analysis,
        }
    )


@app.post("/api/audit")
def post_audit():
    _guard("audit")
    data = _body()
    password = _password(data)

    if not password:
        raise ApiError("invalid_request", "Falta 'password' para poder auditar.", 400)

    redact.register(password)
    analysis = analyzer.analyze(password, _context(data))
    entry = audit.record(
        {
            "event": "audit",
            "audit_id": audit.new_audit_id(),
            "policy_id": analysis["policy_id"],
            "score": analysis["score"],
            "guesses_log10": analysis["guesses_log10"],
            "findings": sorted({f["id"] for f in analysis["findings"]}),
            "pw_hmac": audit.pw_hmac(password),
        }
    )
    return jsonify(
        {
            "audit_id": entry["audit_id"],
            "ts": entry["ts"],
            "receipt": audit.receipt(analysis),
            "score": analysis["score"],
            "findings": sorted({f["id"] for f in analysis["findings"]}),
        }
    )


@app.teardown_request
def _forget_secrets(exception: BaseException | None = None) -> None:
    """Olvida la contraseña de esta petición en cuanto termina.

    Sin esto el registro de secretos crecería sin límite y una contraseña
    seguiría "protegida" en la memoria mucho después de haber dejado de hacer
    falta, que es justo cuando uno ya no recuerda que está ahí.
    """
    redact.clear()


@app.post("/api/hibp")
def post_hibp():
    """Verificación de brechas por k-anonymity.

    El cliente envía solo los 5 primeros hex de SHA-1; el servidor consulta el
    rango y devuelve los sufijos. El hash completo nunca sale del dispositivo,
    así que ni este servidor ni HIBP pueden reconstruir la contraseña.

    En PythonAnywhere Free la salida a Internet está restringida a una lista
    blanca, así que esta ruta probablemente no tenga salida. Se degrada con un
    200 y `available: false` en lugar de un error, para que la interfaz no se
    rompa por un servicio opcional.
    """
    data = _body()
    prefix = data.get("prefix")
    if not isinstance(prefix, str) or len(prefix) != 5 or not all(
        c in "0123456789abcdefABCDEF" for c in prefix
    ):
        raise ApiError(
            "invalid_request",
            "El campo 'prefix' debe ser exactamente 5 caracteres hexadecimales.",
            400,
        )

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    request_obj = urllib.request.Request(
        url,
        headers={"User-Agent": "PassGuard-Lab-educational", "Add-Padding": "true"},
    )
    try:
        with urllib.request.urlopen(request_obj, timeout=3) as response:
            body = response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError):
        return jsonify({"available": False, "found": None, "count": None, "suffixes": []})
    except Exception:  # noqa: BLE001
        return jsonify({"available": False, "found": None, "count": None, "suffixes": []})

    suffixes: list[str] = []
    for line in body.splitlines():
        if ":" not in line:
            continue
        suffix, _, count = line.partition(":")
        suffixes.append(f"{suffix.strip().upper()}:{count.strip()}")
    return jsonify({"available": True, "found": bool(suffixes), "count": len(suffixes), "suffixes": suffixes})


# --------------------------------------------------------------------------- #
# preflight
# --------------------------------------------------------------------------- #

@app.route("/api/<path:_any>", methods=["OPTIONS"])
@app.route("/api", methods=["OPTIONS"])
def options(_any: str = "") -> tuple:
    """Responde al preflight.

    Que el preflight exista es lo que impide que un formulario HTML o un fetch en
    modo no-cors dispare un POST desde otro origen. Un POST simple (que no
    dispara preflight) que intente alcanzar /api/ve el Access-Control-Allow-Origin
    ausente, y el navegador bloquea la respuesta, aunque la petición sí se haya
    procesado: por eso el Origin se valida también en el servidor.
    """
    return ("", 204)


if __name__ == "__main__":
    app.run(
        host=config.host,
        port=config.port,
        debug=config.debug,
        use_reloader=config.debug,
    )
