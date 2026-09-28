"""Redacción de secretos en los logs.

Por qué existe: `logger.exception()` imprime el traceback completo, y el
traceback incluye el mensaje de la excepción. Cualquier error que interpole la
contraseña en su mensaje se la lleva al log:

    raise RuntimeError(f"no puedo analizar {password!r}")
    # -> RuntimeError: no puedo analizar 'LaQueNoDebeSalir#2026'

Eso no es hipotético. Basta un `KeyError(password)`, un `ValueError` de una
librería de validación, o un `assert password in lista` para que el secreto
quede escrito en el archivo de log, que suele ser el sitio con más permisos y
el que nadie revisa.

La defensa tiene dos partes:

1. Cada vez que el servidor conoce una contraseña, la registra aquí como
   secreto activo. No se guarda la contraseña en ningún otro sitio: solo una
   referencia temporal, que se borra al terminar la petición.
2. Antes de escribir al log, todo el texto pasa por `redact()`, que sustituye
   cada secreto conocido por `[redactado]`.

El filtro se aplica manualmente en el punto de escritura y no como
`logging.Filter`, a propósito: los filtros de un logger padre no se aplican a
los registros que llegan por propagación desde los hijos, y aquí no controlamos
los handlers (los configura el servidor WSGI). Redactar justo antes de escribir
es el único sitio que no depende de la configuración ajena.
"""

from __future__ import annotations

import threading

# Separador legible en un log: se distingue de un valor real de un vistazo.
PLACEHOLDER = "[redactado]"

# Los secretos de menos de 6 caracteres se ignoran. Redactar "a" o "123"
# convertiría cada log en un muro de marcadores sin proteger nada, porque un
# valor tan corto se cuela igual y ensucia la lectura.
MIN_SECRET_LENGTH = 6

_lock = threading.Lock()
_secrets: set[str] = set()


def register(value: str | None) -> None:
    """Declara un valor como secreto a redactar durante la petición actual."""
    if not value or len(value) < MIN_SECRET_LENGTH:
        return
    with _lock:
        _secrets.add(value)


def clear() -> None:
    """Olvida todos los secretos. Se llama al terminar cada petición."""
    with _lock:
        _secrets.clear()


def active_count() -> int:
    with _lock:
        return len(_secrets)


def redact(text: str) -> str:
    """Sustituye todos los secretos conocidos dentro de `text`."""
    if not text:
        return text
    with _lock:
        current = set(_secrets)
    if not current:
        return text
    # De más largo a más corto: si un secreto contiene a otro, se redacta el
    # largo primero y el corto no deja restos dentro del marcador.
    for secret in sorted(current, key=len, reverse=True):
        if secret in text:
            text = text.replace(secret, PLACEHOLDER)
    return text


def redacted_repr(value: str | None) -> str:
    """Representación segura de un valor para un mensaje de log."""
    if value is None:
        return "None"
    if len(value) < MIN_SECRET_LENGTH:
        return f"{value}({len(value)} chars)"
    return f"<{len(value)} chars>"
