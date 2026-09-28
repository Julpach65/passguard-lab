"""Errores con forma JSON uniforme.

Motivo: en la versión anterior, cualquier excepción producía una página HTML
con la traza. El cliente hacía `response.json()` sobre HTML, recibía un
SyntaxError, caía al `catch` y dejaba los requisitos congelados con el estado
anterior. El usuario veía "Hubo un error" junto a ticks obsoletos.

Aquí NINGÚN error sale como HTML. Todos son
`{"error": {"code": ..., "message": ...}}` con un código estable que el cliente
puede ramificar, y el mensaje está en español para el usuario final.
"""

from __future__ import annotations

import traceback
from typing import Any

from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException

import redact


class ApiError(Exception):
    """Error de negocio con código estable, pensado para ramificar en el cliente."""

    def __init__(
        self,
        code: str,
        message: str,
        status: int = 400,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.headers = headers or {}

    def to_response(self):
        response = jsonify({"error": {"code": self.code, "message": self.message}})
        response.status_code = self.status
        for key, value in self.headers.items():
            response.headers[key] = value
        return response


def _wants_json() -> bool:
    """Las rutas de API siempre JSON; la UI estática acepta HTML."""
    from flask import request

    return request.path.startswith("/api/")


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(ApiError)
    def _api_error(exc: ApiError):
        return exc.to_response()

    @app.errorhandler(400)
    def _bad_request(exc: HTTPException):
        return jsonify(
            {"error": {"code": "invalid_request", "message": "Petición mal formada."}}
        ), 400

    @app.errorhandler(404)
    def _not_found(exc: HTTPException):
        if _wants_json():
            return jsonify(
                {"error": {"code": "not_found", "message": "Ese recurso no existe."}}
            ), 404
        return jsonify(
            {
                "error": {
                    "code": "not_found",
                    "message": "No se encontró lo que buscabas. Revisa la ruta o vuelve al índice.",
                }
            }
        ), 404

    @app.errorhandler(405)
    def _not_allowed(exc: HTTPException):
        return jsonify(
            {"error": {"code": "method_not_allowed", "message": "Ese método no está permitido aquí."}}
        ), 405

    @app.errorhandler(413)
    def _too_large(exc: HTTPException):
        return jsonify(
            {
                "error": {
                    "code": "payload_too_large",
                    "message": "El cuerpo de la petición excede el máximo permitido.",
                }
            }
        ), 413

    @app.errorhandler(429)
    def _rate_limited(exc: HTTPException):
        return jsonify(
            {
                "error": {
                    "code": "rate_limited",
                    "message": "Demasiadas peticiones. Espera un momento antes de reintentar.",
                }
            }
        ), 429

    @app.errorhandler(Exception)
    def _unhandled(exc: Exception):
        # Nunca se filtra la excepción al cliente, y tampoco al log sin
        # redactar. `logger.exception()` imprimía el traceback entero, y el
        # traceback incluye el mensaje de la excepción: si esa excepción
        # interpola la contraseña, el secreto quedaba escrito en el log.
        #
        # Se formatea el traceback a mano, se redacta, y se registra como un
        # mensaje normal. Así se conserva el diagnóstico completo sin que el
        # archivo de log se convierta en un almacén de secretos.
        detail = "".join(
            traceback.format_exception(type(exc), exc, exc.__traceback__)
        )
        app.logger.error(
            "error no controlado: %s\n%s",
            type(exc).__name__,
            redact.redact(detail),
        )
        payload: dict[str, Any] = {
            "error": {
                "code": "internal_error",
                "message": "Ocurrió un error inesperado en el servidor.",
            }
        }
        return jsonify(payload), 500
