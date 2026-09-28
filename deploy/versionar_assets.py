"""AÃ±ade la versiÃ³n del commit a las referencias de los recursos del sitio.

Por quÃ© existe: GitHub Pages responde con `Cache-Control: max-age=600` y no
permite cambiarlo, asÃ­ que el navegador guarda `styles.css`, `config.js` y
`app.js` diez minutos. Sin mÃ¡s, quien abre la web despuÃ©s de un despliegue
puede estar viendo la versiÃ³n anterior. El sÃ­ntoma es desconcertante porque no
parece un fallo de cachÃ©: la pÃ¡gina anunciaba "modo local Â· sin backend" con el
backend funcionando y el CORS ya resuelto, porque el `config.js` antiguo aÃºn
tenÃ­a `apiBase` vacÃ­o.

Poner `?v=<sha>` cambia la clave de cachÃ©, asÃ­ que cada despliegue entrega URLs
nuevas y la cachÃ© no puede servir nada viejo.

Por quÃ© Python y no `sed`: se intentÃ³ primero con sed, usando `|` como
delimitador porque la ruta de los ficheros lleva `/`. El patrÃ³n necesita `|`
para la alternancia, asÃ­ que el segundo `|` cerraba el patrÃ³n de golpe y sed
fallaba con "unknown option to `s`". El error se cuela en silencio en una
simulaciÃ³n con otro lenguaje, porque allÃ­ los delimitadores no existen. Con
Python el mismo script se ejecuta y se prueba en local antes de subirlo.

Uso:
    python3 deploy/versionar_assets.py [ruta] [sha]

Sin argumentos versiona `static/index.html` con el commit actual. Acepta la
ruta y el sha como argumentos para poder probarlo contra una copia temporal sin
tocar el repositorio, que es como estÃ¡ probado.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

# Solo los tres recursos del sitio. El favicon es un data:URI y las anclas
# internas no son ficheros, asÃ­ que ninguno debe llevar la versiÃ³n.
#
# El patrÃ³n captura el atributo y el nombre por separado, y reconstruye la
# comilla de cierre. Incluirla en el grupo y pegar la versiÃ³n detrÃ¡s la
# colocaba fuera: href="styles.css"?v=abc, que no es una URL vÃ¡lida. La comilla
# tiene que quedar DENTRO.
PATRON = re.compile(
    r'(src|href)="(config\.js|app\.js|styles\.css)"'
)
ESPERADOS = 3


def sha_actual() -> str:
    """Commit corto, o un aviso si no se puede leer."""
    try:
        salida = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"::warning::no se pudo leer el sha de git: {exc}")
        return "dev"
    return salida.stdout.strip() or "dev"


def versionar(ruta: pathlib.Path, sha: str) -> int:
    """Reescribe el HTML y devuelve cuÃ¡ntos recursos quedaron versionados."""
    original = ruta.read_text(encoding="utf-8")
    nuevo, cambios = PATRON.subn(rf'\1="\2?v={sha}"', original)
    ruta.write_text(nuevo, encoding="utf-8")
    return cambios


def main(argv: list[str]) -> int:
    destino = pathlib.Path(argv[1]) if len(argv) > 1 else pathlib.Path("static/index.html")
    sha = argv[2] if len(argv) > 2 else sha_actual()

    if not destino.is_file():
        print(f"::error::no existe {destino}")
        return 1

    cambios = versionar(destino, sha)
    print(f"recursos versionados: {cambios} (se esperan {ESPERADOS}) con ?v={sha}")

    if cambios == 0:
        # Cero es el fallo que importa: el patrÃ³n dejÃ³ de encajar con el HTML,
        # y sin este error el despliegue se publicarÃ­a tal cual, con la
        # versionado roto y sin que nadie se entere hasta que vuelva a pasar.
        print(
            "::error::el patrÃ³n no versionÃ³ nada. Revisa los src/href de "
            f"{destino}."
        )
        return 1

    if cambios != ESPERADOS:
        print(
            f"::warning::versionados {cambios} de {ESPERADOS}. Si has aÃ±adido "
            "un recurso nuevo, aÃ±Ã¡delo al patrÃ³n de deploy/versionar_assets.py."
        )

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
