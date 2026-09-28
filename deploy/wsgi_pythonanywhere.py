"""Fichero WSGI de PythonAnywhere, listo para pegar.

PythonAnywhere no tiene ningún campo de variables de entorno en su panel. El
único sitio donde el proceso web las ve es este fichero, porque es lo único
que se ejecuta antes de servir nada. Por eso `PASSGUARD_ALLOWED_ORIGINS` va
aquí dentro y no en un `export` suelto: un `export` en la consola Bash sí
funciona, pero solo en esa consola, y el fallo clásico es ponerlo ahí, ver que
la consola sí lo ve, y que la web siga devolviendo 403.

Cómo usarlo:

  1. Pestaña **Web** de https://www.pythonanywhere.com
  2. En el bloque de la web app, arriba del todo, el enlace
     **WSGI configuration file** (apunta a
     /var/www/julpach65_pythonanywhere_com_wsgi.py)
  3. Seleccionar todo el contenido y pegar este fichero entero
  4. Guardar, y botón **Reload** en la misma pestaña

El `sys.path` va primero a propósito. Este fichero vive en /var/www/, fuera del
proyecto, y PythonAnywhere solo añade su propio directorio a la ruta. Como
`wsgi.py` hace `from app import app`, sin esa línea el import falla con
ModuleNotFoundError y la web responde 502.

El alias `as application` tampoco es cosmético: PythonAnywhere busca una
variable llamada exactamente `application` en este fichero. Sin el alias no
encuentra nada que servir.

Sobre el valor de PASSGUARD_ALLOWED_ORIGINS:

- Sin la subruta `/passguard-lab`, porque la cabecera `Origin` nunca la lleva.
- Es una lista separada por comas, así que admite varios orígenes:
  "https://un.sitio,https://otro.sitio"
- No hace falta tocar nada más. PASSGUARD_CORPUS_PATH ya tiene un valor por
  defecto que resuelve al corpus dentro del proyecto, y la clave de firma se
  genera en memoria al arrancar, así que no hay ningún otro secreto que
  declarar.
"""

import os
import sys

# --- 1. El proyecto en la ruta de importacion -------------------------------
# Debe ir antes del import de wsgi, o el import falla.
PROJECT_PATH = '/home/Julpach65/passguard-lab'
if PROJECT_PATH not in sys.path:
    sys.path.insert(0, PROJECT_PATH)

# --- 2. Configuracion que solo puede leer el proceso web -------------------
# Origen de GitHub Pages que puede llamar a la API. Sin esta linea el navegador
# recibe 403 en el preflight y la web cae en modo local, que no es lo mismo que
# una API caida: aqui el veredicto lo calcula el espejo del cliente.
os.environ['PASSGUARD_ALLOWED_ORIGINS'] = 'https://julpach65.github.io'

# --- 3. El objeto que PythonAnywhere va a servir ---------------------------
from wsgi import app as application  # noqa: E402
