"""Punto de entrada WSGI.

PythonAnywhere no usa Procfile: en el panel web se indica el módulo y el objeto
que debe cargar. Este archivo existe para que ese objeto tenga un nombre
estable (`wsgi:app`) y para poder arrancar en local con el servidor de
desarrollo.

Se exporta un único nombre a propósito. Si el panel pidiera `application`, se
cambia aquí y el cambio queda visible en el diff; mantener dos alias "por si
acaso" es la forma más sencilla de que acaben divergiendo.
"""

from app import app

__all__ = ["app"]
