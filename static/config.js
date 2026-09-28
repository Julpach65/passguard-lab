/* ==========================================================================
   PassGuard - configuración de despliegue
   --------------------------------------------------------------------------
   Este es el único archivo que hay que editar tras desplegar el backend.

   apiBase
     - Vacío (""): la página se queda en MODO LOCAL. No se consulta ningún
       servidor, el análisis se resuelve en el navegador y se avisa en pantalla
       de que el veredicto es una estimación. Es el valor correcto para abrir
       index.html desde el disco (file://), porque file:// no tiene /api.
     - URL absoluta: las peticiones van a ese host. Sin barra final y sin /api,
       porque app.js ya añade /api/... por su cuenta.

     Antes de rellenar esto, el servidor tiene que permitir este origen. En
     PythonAnywhere:

       Web -> Edit -> Environment variables -> Add
       PASSGUARD_ALLOWED_ORIGINS = https://<USUARIO>.github.io
       (después, Reload)

     Sin esa variable el navegador bloquea la respuesta y la página cae en
     modo local. La lista blanca NO admite comodines: es un origen exacto, sin
     ruta, sin barra final.

     Ejemplo de desarrollo con la arquitectura partida en dos puertos:
       1. python app.py                      -> API en http://127.0.0.1:5000
       2. python -m http.server 8000 --directory static
       3. abre http://localhost:8000/         -> el frontend
       4. pon aquí apiBase: "http://127.0.0.1:5000"
     http://localhost:8000 ya está permitido por defecto en el servidor.

     Ejemplo tras desplegar en PythonAnywhere y servir la página en Pages:
       apiBase: "https://TU-CUENTA.pythonanywhere.com",

   Verificación de brechas
     /api/hibp sigue disponible como endpoint, pero la interfaz no lo llama:
     no se consulta ningún servicio externo desde el navegador. Para usarlo,
     manda {"prefix": "<5 primeros hex del SHA-1>"} y nunca la contraseña.
   ========================================================================== */

window.PASSGUARD_CONFIG = {
  apiBase: ""
};
