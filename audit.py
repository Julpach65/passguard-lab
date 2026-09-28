"""Auditoría sin retener el secreto.

Regla dura, y es la que hace defendible este módulo: NUNCA se registra la
contraseña, ni un hash de ella, ni un prefijo. Lo que se registra es

    HMAC-SHA256(clave_de_32_bytes, contraseña)

La clave se genera al arrancar el proceso, vive solo en memoria y nunca se
persiste ni se versiona. Reiniciar el servicio invalida los recibos previos, que
es el comportamiento correcto para este propósito.

Qué permite: demostrar que un análisis se emitió con una política y un corpus
concretos, y detectar reutilización (el mismo HMAC apareciendo varias veces) SIN
que exista en ningún sitio un valor del que recuperar la contraseña. Sin el HMAC,
detectar reutilización obligaría a guardar el secreto, y guardar el secreto es
exactamente el problema.

`assert_no_secret_in_logs` existe para que el test suite pueda probarlo en
lugar de afirmarlo, y `redact` garantiza que ningún texto con el secreto llegue
al log aunque una excepción lo interpole en su mensaje.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
import uuid
from typing import Any

import redact
from config import config

_SECRET = config.secret_key

# Logger dedicado: así el flujo de auditoría se puede filtrar o silenciar sin
# tocar el resto, y los tests lo capturan por separado.
LOG = logging.getLogger("passguard.audit")


def pw_hmac(password: str) -> str:
    """Huella irreversible de la contraseña, con clave del servidor."""
    return hmac.new(_SECRET, password.encode("utf-8"), hashlib.sha256).hexdigest()


def sign(payload: bytes) -> str:
    return base64.urlsafe_b64encode(
        hmac.new(_SECRET, payload, hashlib.sha256).digest()
    ).decode("ascii").rstrip("=")


def receipt(analysis: dict[str, Any]) -> str:
    """Firma lo esencial de un análisis para poder reproducirlo y verificarlo."""
    body = json.dumps(
        {
            "policy_id": analysis.get("policy_id"),
            "policy_version": analysis.get("policy_version"),
            "score": analysis.get("score"),
            "guesses_log10": analysis.get("guesses_log10"),
            "entropy_bits": analysis.get("entropy_bits"),
            "findings": sorted({f.get("id", "") for f in analysis.get("findings", [])}),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"{base64.urlsafe_b64encode(body).decode('ascii').rstrip('=')}.{sign(body)}"


def record(entry: dict[str, Any]) -> dict[str, Any]:
    """Escribe una línea de log estructurada. Sin excepciones en el camino.

    Va al logger y no a `print`/`sys.stderr.write` por dos razones. La primera es
    que stderr se salta cualquier filtro, incluida la redacción de secretos. La
    segunda es que una línea suelta a stderr no se puede filtrar por nivel ni
    silenciar en un entorno de pruebas, y estas pruebas necesitan poder
    capturarla para comprobar que la contraseña no aparece.
    """
    entry = {**entry, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    line = json.dumps(entry, sort_keys=True, ensure_ascii=False)
    try:
        # La redacción se aplica aquí, en el último punto antes de escribir.
        LOG.info(redact.redact(line))
    except Exception:  # noqa: BLE001 - el log nunca debe romper la petición
        pass
    return entry


def new_audit_id() -> str:
    return uuid.uuid4().hex[:8]


def assert_no_secret_in_logs(password: str, stream) -> bool:
    """Comprueba que `password` no aparezca en el texto capturado.

    Esta función NO puede prometer nada por sí sola. El argumento `stream` tiene
    que ser el texto que el test ya capturó de los loggers; leer `sys.stderr`
    desde aquí devolvería una flujo distinto del que usa la aplicación, y la
    comprobación siempre pasaría. Por eso el parámetro es obligatorio y no tiene
    valor por defecto: la versión anterior aceptaba omitirlo y terminaba en un
    `or True` que devolvía True sin comprobar nada.

    Devuelve True si está limpio. No lanza, para que el test pueda inspeccionar
    el motivo del fallo.
    """
    if password is None:
        return True
    text = stream.read() if hasattr(stream, "read") else str(stream)
    return password not in text
