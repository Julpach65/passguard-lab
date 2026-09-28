"""Limitación de tasa por IP, cubo de tokens en memoria.

Por qué hace falta: en la versión anterior no había ninguna. Con el
`while True` de app.py:12-21, cuatro peticiones con `{"length": 5}` bastaban
para clavar cuatro hilos al 100% de CPU y dejar la aplicación sin responder.
Un límite de tasa no evita el bug, pero acota el daño a quien lo dispara.

Es deliberadamente en memoria y sin dependencia externa: el objetivo es
disuadir el abuso trivial, no ser un store distribuido. En PythonAnywhere
(instance única) es adecuado. Con varias instancias, esto pasaría a ser
inconsistente y haría falta Redis.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class TokenBucket:
    """Permite `limit` peticiones por ventana de `window` segundos, por clave."""

    def __init__(self, limit: int, window: int) -> None:
        self.limit = max(1, limit)
        self.window = max(1, window)
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, int]:
        """Devuelve (permitido, retry_after_en_segundos)."""
        now = time.monotonic()
        with self._lock:
            bucket = self._hits[key]
            cutoff = now - self.window
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self.limit:
                retry_after = max(1, int(bucket[0] + self.window - now) + 1)
                return False, retry_after
            bucket.append(now)
            return True, 0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


class RateLimiter:
    """Conjunto de cubos, uno por tipo de endpoint."""

    def __init__(self, window: int) -> None:
        self._buckets: dict[str, TokenBucket] = {}
        self._window = window

    def register(self, name: str, limit: int) -> None:
        self._buckets[name] = TokenBucket(limit, self._window)

    def check(self, name: str, key: str) -> tuple[bool, int]:
        bucket = self._buckets.get(name)
        if bucket is None:
            return True, 0
        return bucket.check(key)

    def reset(self) -> None:
        for bucket in self._buckets.values():
            bucket.reset()

    def sweep(self) -> None:
        """Poda claves inactivas para que el diccionario no crezca sin límite.

        Un atacante que varíe su IP por petición podría hacer crecer el mapa de
        forma indefinida. Se llama periódicamente desde el arranque de la app.
        """
        now = time.monotonic()
        for bucket in self._buckets.values():
            with bucket._lock:
                stale = [
                    key
                    for key, hits in bucket._hits.items()
                    if not hits or hits[-1] + bucket.window <= now
                ]
                for key in stale:
                    del bucket._hits[key]


def client_key(forwarded_for: str | None, remote_addr: str | None) -> str:
    """Identificador de cliente para el cubo.

    Se usa X-Forwarded-For porque detrás de un proxy o de un túnel el
    remote_addr real es la IP del proxy. Se toma el primer elemento de la
    cadena, que es el cliente original según el convenio.
    """
    if forwarded_for:
        first = forwarded_for.split(",")[0].strip()
        if first:
            return first
    return remote_addr or "unknown"
