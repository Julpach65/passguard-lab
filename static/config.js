/* ==========================================================================
   PassGuard Lab - configuración de despliegue
   --------------------------------------------------------------------------
   ESTE ES EL ÚNICICO ARCHIVO QUE HAY QUE EDITAR TRAS DESPLEGAR EL BACKEND.

   apiBase
     - Vacío (""): las peticiones van al mismo origen que sirve esta página.
       Es lo correcto cuando el frontend y el backend se sirven juntos.
     - URL absoluta: las peticiones van a ese host, por ejemplo
       "https://TU-CUENTA.pythonanywhere.com" (sin barra final y sin /api,
       porque esta app ya añade /api/... por su cuenta).
     - Si abres index.html directamente desde el disco (file://) y apiBase sigue
       vacío, no hay backend posible: la aplicación arranca en MODO LOCAL y
       todo el análisis se resuelve en el navegador.
     - Si la página se sirve desde GitHub Pages y apiBase sigue vacío, ocurre
       lo mismo por otra razón: Pages no ejecuta Python, así que el origen de
       la página no tiene /api. La aplicación se queda en MODO LOCAL y lo dice
       en pantalla. Rellena apiBase para que la API de PythonAnywhere atienda.

   Para probar la arquitectura dividida en local, con el frontend en un puerto
   y la API en otro:
     1. python app.py                      -> API en http://127.0.0.1:5000
     2. python -m http.server 8000 --directory static
     3. abre http://localhost:8000/         -> el frontend
     4. pon aquí apiBase: "http://127.0.0.1:5000"
   El origen http://localhost:8000 ya está en la lista blanca por defecto.

   hibpEnabled
     true  = activa la verificación de brechas (POST /api/hibp).
     false = la omite; el resto de la aplicación no se ve afectado.
     (también se acepta la grafía antigua hibrEnabled)

   Ejemplo tras desplegar el backend en PythonAnywhere:
     apiBase: "https://TU-CUENTA.pythonanywhere.com",
   ========================================================================== */

window.PASSGUARD_CONFIG = {
  apiBase: "",
  hibpEnabled: true
};
