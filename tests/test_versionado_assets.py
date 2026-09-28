"""El versionado de recursos del despliegue, verificado con código.

`deploy/versionar_assets.py` reescribe el `index.html` de la copia de trabajo
justo antes de publicarlo, para que las referencias lleven `?v=<sha>` y la
caché del navegador no pueda servir la versión anterior. GitHub Pages obliga a
`max-age=600` y no deja cambiarlo, así que esa query es la única defensa.

El motivo de que esto tenga tests es histórico, no estadístico. La primera
versión de este paso era un `sed` de una línea, y falló en el primer despliegue
con `unknown option to 's'`, porque se usó `|` como delimitador y el patrón
necesitaba `|` para la alternancia. La segunda versión tenía otro fallo distinto
y más silencioso: la query se pegaba fuera de las comillas, dejando
`href="styles.css"?v=abc`, que es una URL inválida. Los dos habrían pasado
desapercibidos de no probarse contra el HTML de verdad.

Así que los tests no comprueban que el script "funciona": comprueban que el HTML
que sale por detrás es el que un navegador puede pedir, y que el paso falla
ruidosamente cuando deja de encajar con el `index.html` real.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
SCRIPT = RAIZ / "deploy" / "versionar_assets.py"
INDEX_REAL = RAIZ / "static" / "index.html"

# Referencia completa de un recurso del sitio, con la query dentro de las
# comillas. Es la forma correcta; la incorrecta es `href="x.css"?v=abc`.
BIEN = re.compile(r'(?:src|href)="(?:config\.js|app\.js|styles\.css)\?v=[0-9a-zA-Z._-]+"')
# Cualquier `?v=` que se escape fuera del valor del atributo.
FUERA = re.compile(r'"[^"]*"\?v=')
VERSIONADO = re.compile(r'\?v=[0-9a-zA-Z._-]+')


def ejecutar(destino: Path, sha: str = "abc1234") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(destino), sha],
        capture_output=True,
        text=True,
    )


@pytest.fixture()
def copia_index(tmp_path: Path) -> Path:
    """Copia real del `index.html` del repo.

    El script se ejecuta como proceso aparte, igual que en CI, y sobre una copia
    para no ensuciar el árbol de trabajo al probar.
    """
    destino = tmp_path / "index.html"
    shutil.copy(INDEX_REAL, destino)
    return destino


def test_el_script_existe():
    """Si alguien borra el script, el workflow falla con 'file not found'."""
    assert SCRIPT.is_file(), "deploy/versionar_assets.py no existe"


def test_versiona_los_tres_recursos(copia_index: Path):
    """Los tres recursos del sitio llevan la versión."""
    resultado = ejecutar(copia_index)
    assert resultado.returncode == 0, resultado.stdout + resultado.stderr

    html = copia_index.read_text(encoding="utf-8")
    encontrados = BIEN.findall(html)
    assert len(encontrados) == 3, f"esperaba 3 referencias bien formadas, encontré {encontrados}"


def test_la_query_queda_dentro_de_las_comillas(copia_index: Path):
    """Regresión del fallo `href="x.css"?v=abc`, que es una URL inválida.

    El navegador pediría un atributo llamado `"?v=abc"` y un atributo `href` sin
    ruta: la hoja de estilos desaparecería sin error visible en la consola.
    """
    html = copia_index.read_text(encoding="utf-8")
    fuera = FUERA.findall(html)
    assert not fuera, f"la ?v= se ha colado fuera del atributo: {fuera}"


def test_no_toca_el_favicon_ni_las_anclas(copia_index: Path):
    """El favicon es un data:URI y las anclas no son ficheros.

    Versionarlos no solo es inútil: un `data:...` con query puede dejar de
    resolverse, y una ancla con query ya no encuentra su destino.
    """
    resultado = ejecutar(copia_index)
    assert resultado.returncode == 0, resultado.stdout + resultado.stderr

    html = copia_index.read_text(encoding="utf-8")
    assert 'href="#panel-analizador"' in html, "el ancla de salto se ha roto"
    assert not re.search(r'data:image[^"]*\?v=', html), "el favicon lleva query"
    assert len(VERSIONADO.findall(html)) == 3, "hay más query de las esperadas"


def test_falla_mas_vocativo_si_no_encuentra_nada(tmp_path: Path):
    """Cero coincidencias es el fallo que importa y debe tumbar el despliegue.

    Sin esto, un `index.html` que cambie de forma se publicaría sin versionar y
    el fallo se descubriría semanas después, en el navegador de otra persona.
    """
    destino = tmp_path / "otro.html"
    destino.write_text('<script src="vendor.js"></script>', encoding="utf-8")

    resultado = ejecutar(destino)
    assert resultado.returncode == 1, "con 0 coincidencias debería salir con 1"
    assert "::error::" in resultado.stdout, "el fallo debe quedar anotado en el log de Actions"


def test_avisa_pero_no_falla_si_falta_uno(tmp_path: Path):
    """Si se añade un cuarto recurso y no está en el patrón, avisa pero publica.

    Fallar aquí sería peor: dejaría el sitio sin desplegar por un fichero nuevo
    que aún no está en el patrón. El aviso basta para que se note en el log.
    """
    destino = tmp_path / "parcial.html"
    destino.write_text('<link href="styles.css"><script src="app.js"></script>', encoding="utf-8")

    resultado = ejecutar(destino)
    assert resultado.returncode == 0, "un recurso de menos no debe impedir el despliegue"
    assert "::warning::" in resultado.stdout, "debería avisar de que falta uno"


def test_falla_si_el_fichero_no_existe(tmp_path: Path):
    """Un paso que no distingue 'no existe' de 'no coincide' no sirve de nada."""
    resultado = ejecutar(tmp_path / "no-existe.html")
    assert resultado.returncode == 1
    assert "::error::" in resultado.stdout


def test_el_sha_por_defecto_sale_de_git(copia_index: Path):
    """Sin sha explícito, usa el commit actual.

    Es lo que hace el workflow. Si se rompiera la lectura de git, el despliegue
    publicaría `?v=dev` en todas partes y la cache seguiría rota, pero sin
    ningún error visible en el log.
    """
    esperado = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        capture_output=True,
        text=True,
        cwd=RAIZ,
        check=True,
    ).stdout.strip()

    resultado = subprocess.run(
        [sys.executable, str(SCRIPT), str(copia_index)],
        capture_output=True,
        text=True,
        cwd=RAIZ,
    )
    assert resultado.returncode == 0, resultado.stdout + resultado.stderr

    html = copia_index.read_text(encoding="utf-8")
    assert f"?v={esperado}" in html, f"esperaba la query ?v={esperado} en el HTML"
    assert "?v=dev" not in html, "se ha usado el sha de reserva en vez del de git"

