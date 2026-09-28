"""Configuración de pytest compartida por toda la suite.

Deja el repo en `sys.path` para que `import analyzer` resuelva contra los
módulos locales, y expone el `client` de Flask con el rate limiter limpio.
El fixture vive aquí, y no en un módulo de test, porque lo usan los tres
archivos de pruebas.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("PASSGUARD_ENV", "test")

# El corpus tiene que existir antes de que analyzer lo busque. En un clon
# limpio se genera aquí para que `pytest` funcione sin pasos manuales.
CORPUS = ROOT / "data" / "corpus.txt"
if not CORPUS.exists():
    import subprocess

    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "build_corpus.py")],
        check=True,
        capture_output=True,
    )


@pytest.fixture
def client():
    """Cliente de Flask con el rate limiter reseteado antes y después.

    El límite por IP es real (10 generaciones por minuto) y sin reset las
    pruebas de bucle se comerían su propio presupuesto hasta recibir 429.
    """
    import app as app_module

    app_module.limiter.reset()
    with app_module.app.test_client() as test_client:
        yield test_client
    app_module.limiter.reset()
