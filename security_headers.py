"""Cabeceras de seguridad y CORS.

Decisión importante y no trivial: la versión anterior NO tenía CORS, y eso era
lo correcto, porque el frontend y el backend compartían origen. En cuanto el
frontend pasa a GitHub Pages y el backend a PythonAnywhere, son orígenes
distintos y el navegador bloquea por defecto.

La tentación sería responder `Access-Control-Allow-Origin: *`. Eso sería un
error grave: permitiría que cualquier sitio del mundo ejecute peticiones
contra esta API desde el navegador de un visitante.

Aquí la lista blanca es explícita y el `Origin` se valida también en el
servidor, porque CORS protege la LECTURA de la respuesta, no la ejecución de la
petición. Una web attackante puede disparar el POST; lo que no puede es leer la
respuesta, y el preflight que exige `X-Passguard-Client` impide que la petición
ni siquiera llegue a ejecutarse desde el navegador.
"""

from __future__ import annotations

from flask import Flask, Response, request

from config import config
from errors import ApiError

CLIENT_HEADER = "X-Passguard-Client"
ALLOWED_METHODS = "GET, POST, OPTIONS"
ALLOWED_HEADERS = f"Content-Type, {CLIENT_HEADER}"
EXPOSED_HEADERS = "Retry-After"
MAX_AGE = "600"
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _csp() -> str:
    """CSP que permite los estilos y las peticiones que la app realmente usa.

    connect-src incluye los orígenes de la lista blanca, que es donde vive el
    backend. Se evita 'unsafe-inline' en script-src: todo el JavaScript es
    externo, así que no hay necesidad de abrir esa puerta.
    """
    connect = " ".join(["'self'", *config.allowed_origins])
    return "; ".join(
        (
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self' https://fonts.googleapis.com",
            "font-src 'self' https://fonts.gstatic.com",
            f"connect-src {connect}",
            "img-src 'self' data:",
            "base-uri 'none'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "object-src 'none'",
        )
    )


def apply(response: Response) -> Response:
    origin = request.headers.get("Origin")
    if origin and config.origin_allowed(origin):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Methods"] = ALLOWED_METHODS
        response.headers["Access-Control-Allow-Headers"] = ALLOWED_HEADERS
        response.headers["Access-Control-Expose-Headers"] = EXPOSED_HEADERS
        response.headers["Access-Control-Max-Age"] = MAX_AGE

    response.headers["Content-Security-Policy"] = _csp()
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

    # Las respuestas de API contienen datos derivados de la contraseña del
    # usuario. Sin no-store, quedan en la caché del navegador y en el disco que
    # usa DevTools para exportar el HAR.
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
    else:
        response.headers.setdefault("Cache-Control", "no-cache")
    return response


def guard() -> None:
    """Rechaza en el servidor lo que CORS por sí solo no puede impedir.

    CORS protege la LECTURA de la respuesta, no la ejecución de la petición: un
    sitio atacante sí puede lanzar el POST contra esta API, y lo único que
    impide que lo lea es el navegador. Por eso el `Origin` se comprueba aquí, en
    el servidor, y por eso una escritura entre orígenes además tiene que
    declarar `X-Passguard-Client`: es la misma condición que ya exige el
    preflight, pero exigida en el backend y no en la promesa del navegador.

    Las peticiones SIN `Origin` siguen passando. No son peticiones de navegador
    entre sitios (curl, wget, el comprobador de salud de PythonAnywhere, las
    pruebas) y bloquearlas no aportaría seguridad: partirían de no tener a
    ninguna web atacante delante, solo de la red.
    """
    if not request.path.startswith("/api/"):
        return

    origin = request.headers.get("Origin")
    if not origin:
        return

    if not config.origin_allowed(origin):
        raise ApiError(
            "origin_not_allowed",
            "Este origen no está autorizado para usar la API.",
            status=403,
        )

    if request.method in WRITE_METHODS and request.headers.get(CLIENT_HEADER) != "1":
        raise ApiError(
            "client_header_required",
            f"Falta la cabecera {CLIENT_HEADER} que exige esta API.",
            status=403,
        )


def register(app: Flask) -> None:
    app.before_request(guard)
    app.after_request(apply)
