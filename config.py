"""Configuración de la aplicación, leída exclusivamente del entorno.

Regla de diseño: ninguna configuración se hornea en el código. En producción
el servidor define las variables de entorno y la aplicación únicamente las
lee. Los valores por defecto están pensados para desarrollo local; son
deliberadamente inseguros para un despliegue público y por eso DEBUG y el host
NO tienen defaults permisivos.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass

VERSION = "1.0.0"
SERVICE_NAME = "passguard-api"

_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

_FALSEY = {"0", "false", "no", "off", ""}


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in _FALSEY


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_list(name: str, default: str) -> tuple[str, ...]:
    raw = os.environ.get(name, default)
    items = (chunk.strip().rstrip("/") for chunk in raw.split(","))
    return tuple(item for item in items if item)


@dataclass(frozen=True)
class Config:
    """Instantánea inmutable de la configuración, resuelta al importar el módulo."""

    debug: bool
    host: str
    port: int
    allowed_origins: tuple[str, ...]
    max_content_length: int
    rate_limit_window: int
    rate_limit_analyze: int
    rate_limit_generate: int
    rate_limit_audit: int
    secret_key: bytes
    corpus_path: str
    version: str = VERSION
    service: str = SERVICE_NAME

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            # DEBUG y HOST no tienen default permisivo a propósito: el valor por
            # defecto es el seguro, porque un despliegue público que olvide
            # definirlos no debe quedar expuesto.
            debug=_env_bool("PASSGUARD_DEBUG", False),
            host=os.environ.get("PASSGUARD_HOST", "127.0.0.1"),
            port=_env_int("PASSGUARD_PORT", 5000),
            allowed_origins=_env_list(
                "PASSGUARD_ALLOWED_ORIGINS",
                "http://localhost:8000,http://127.0.0.1:8000",
            ),
            # 8 KiB. Es suficiente para {"password": "..."} con 128 caracteres
            # de política y corta en seco el vector de cuerpo ilimitado.
            max_content_length=_env_int("PASSGUARD_MAX_CONTENT_LENGTH", 8 * 1024),
            rate_limit_window=_env_int("PASSGUARD_RATE_WINDOW", 60),
            rate_limit_analyze=_env_int("PASSGUARD_RATE_ANALYZE", 30),
            rate_limit_generate=_env_int("PASSGUARD_RATE_GENERATE", 10),
            rate_limit_audit=_env_int("PASSGUARD_RATE_AUDIT", 10),
            # Clave de 32 bytes efímera: vive solo en memoria del proceso, nunca
            # se persiste ni se versiona. Reiniciar el servicio invalida todos
            # los recibos previos, que es el comportamiento correcto.
            secret_key=secrets.token_bytes(32),
            corpus_path=os.environ.get(
                "PASSGUARD_CORPUS_PATH",
                os.path.join(_PROJECT_ROOT, "data", "corpus.txt"),
            ),
        )

    def origin_allowed(self, origin: str | None) -> bool:
        """Valida el header Origin contra la lista blanca, con comparación
        insensible a mayúsculas y sin comodines.

        Un origen ausente (p. ej. curl, o un cliente no-navegador) se permite a
        propósito: CORS es un mecanismo de navegador, no una autenticación.
        La protección real contra orígenes ajenos la aporta el preflight que
        exige el header X-Passguard-Client.
        """
        if origin is None:
            return True
        return origin.rstrip("/").lower() in {o.lower() for o in self.allowed_origins}


config = Config.from_env()
