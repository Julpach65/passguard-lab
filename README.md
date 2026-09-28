# PassGuard Lab

Laboratorio de análisis de contraseñas para la asignatura de Seguridad de la
Información (UPSIN, Universidad de Sincelejo). Estima la entropía de una
contraseña, la contrasta contra un diccionario de contraseñas comunes, la
evalúa contra una política institucional explícita y genera contraseñas que la
cumplen.

La tesis del proyecto, y la razón de que exista una mitad servidor: **cumplir
las reglas de composición no demuestra que una contraseña sea segura.** Una
contraseña puede pasar mayúscula, minúscula, número, símbolo y longitud, y aun
así tener un espacio de búsqueda de 32 combinaciones. Por eso el veredicto
depende de una estimación de entropía y de un contraste contra un corpus, no
solo de cinco casillas.

## Arquitectura

Dos piezas en Review deployments distintos, porque cada una tiene una
restricción propia:

| Pieza | Dónde | Por qué |
| --- | --- | --- |
| Frontend | GitHub Pages | HTML, CSS y JavaScript sin dependencias ni build. Es estático y gratuito. |
| API | PythonAnywhere (Free) | El veredicto se calcula en Python, en el servidor. |

El frontend es una **pintura, no la autoridad**. No lleva su propio veredicto:
manda la contraseña, espera al servidor y pinta lo que llega. Si el servidor no
responde, cambia a un análisis local reducido y **lo dice en pantalla**, porque
sin servidor no se puede consultar el diccionario de contraseñas comunes y un
veredicto local sin avisar sería una mentira. El cliente puede mentir sobre la
política; el servidor no.

La web tiene dos tarjetas y nada más: un probador y un generador. Todo lo demás
—auditoría, verificación de brechas, métricas de tiempo de ruptura— existe como
endpoint de la API, pero no tiene botón. Veredicto, nivel, bits y el motivo por
el que falla, en una línea.

```
static/                 GitHub Pages
  index.html            probador + generador
  styles.css
  app.js                análisis local de respaldo + llamada a la API
  config.js             única línea a editar tras el despliegue

app.py, analyzer.py…    PythonAnywhere
```

## Puesta en marcha local

```bash
python -m venv .venv
.venv\Scripts\activate          # en Windows
pip install -r requirements.txt

python scripts/build_corpus.py # genera data/corpus.txt
python app.py                  # http://127.0.0.1:5000
```

El corpus se construye con `scripts/build_corpus.py`, que es determinista: la
misma semilla produce siempre el mismo fichero. Aun así se versiona (36 KB, 3.755
entradas) para que clonar y ejecutar `pytest` funcione sin ningún paso extra. Los
tests lo regeneran solos si falta.

Con `apiBase` vacío la página arranca en **modo local**: no consulta a nadie y
calcula una estimación en el navegador, avisa de ello y deja la lista de reglas
marcada como provisional. Para probar la arquitectura dividida tal como queda en
producción —frontend en un puerto, API en otro— hay que rellenar `apiBase` en
`static/config.js`:

```bash
python -m http.server 8000 --directory static
```

y poner en `static/config.js`:

```javascript
apiBase: 'http://127.0.0.1:5000'
```

`http://localhost:8000` y `http://127.0.0.1:8000` ya están en la lista blanca por
defecto, así que el CORS funciona sin configurar nada.

## Pruebas

```bash
pytest -q
```

98 pruebas repartidas en cuatro ficheros, y cada una falla por un motivo
distinto:

| Fichero | Qué fija |
| --- | --- |
| `tests/test_analyzer.py` | La aritmética de entropía, el diccionario, l33t, teclado, repeticiones, fechas y contexto. |
| `tests/test_api.py` | Validación de entrada, códigos de error, límites, CORS, cabeceras y el guard de origen. |
| `tests/test_no_log_leak.py` | Que la contraseña no llegue al log ni en un error 500 con traceback. |
| `tests/test_frontend_contract.py` | Que `app.js`, `index.html` y la API no se desincronicen. |

El último es el que más vale, porque el navegador puede editar cualquier
constante: un campo renombrado en `analyzer.py` sin tocar `app.js` se rompe en
producción y no se ve en ningún otro sitio. Fijado sobre el código real de
`static/`, leído del disco:

- Los endpoints que llama el cliente existen en Flask.
- Los `id` que `app.js` busca existen en `index.html`, y `aria-*` y `for` no
  apuntan a nada. Un `getElementById` que devuelve `null` no lanza ningún error:
  la tarjeta desaparece y la página parece seguir funcionando.
- `index.html` no carga ningún fichero inexistente.
- Los campos que el cliente lee de cada respuesta están en la respuesta, y los
  que manda son los que la API acepta. Esta última dirección es la que faltaba:
  los tests del servidor mandaban sus propios payloads, así que una clave mal
  escrita en `app.js` se rompía en el navegador y en ningún test.
- El cliente no manda ningún veredicto ya calculado, y el espejo de política
  (reglas, escala y reglas críticas) coincide con `policy.py`.

Ese espejo merece una frase aparte, porque es una duplicación que se acepta a
propósito. Sin servidor la página no puede consultar el corpus de 3.755
contraseñas, y un espejo desalineado aprobaría en local lo que el servidor
rechaza. Los tests comparan sus 11 reglas y sus reglas críticas una a una con
`policy.py`, así que la divergencia salta en la suite y no en una demostración.

Y la regla que gobierna todo el respaldo local: **el cliente no puede ser más
estricto que el servidor.** Ser más laxo es un aviso; rechazar de más es
mentir, solo que al revés. Por eso `REPEAT_MIN_LENGTH` en `app.js` tiene que
valer lo mismo que `min_length` en `patterns.py`: cuando el cliente marcaba
cualquier carácter repetido dos veces y el servidor exigía bloques de tres,
`Qaa1b2c3d4e5!` pasaba en el servidor y se rechazaba sin servidor. El único
criterio que el respaldo local deja de lado es la nota, y por eso se llama
`estimación local`.

## API

Todas las respuestas de error tienen la misma forma, para que el cliente pueda
ramificar sin parsear texto:

```json
{"error": {"code": "origin_not_allowed", "message": "Este origen no está autorizado para usar la API."}}
```

| Método | Ruta | Entrada | Qué hace |
| --- | --- | --- | --- |
| `GET` | `/api/health` | — | Estado, versión e identificador de política. |
| `GET` | `/api/policy` | — | La política completa que la interfaz usa para construir sus reglas. |
| `POST` | `/api/analyze` | `password`, `context?` | Análisis completo: entropía, veredicto, hallazgos, tiempo de ruptura. |
| `POST` | `/api/generate` | `length?`, `alphabet?`, `groups?`, `min_classes?`, `avoid_ambiguous?` | Genera una contraseña y la analiza. |
| `POST` | `/api/audit` | `password` | Recibo firmado del análisis y línea de auditoría sin el secreto. Sin botón en la web. |
| `POST` | `/api/hibp` | `prefix` | Consulta de brechas por k-anonimato, con solo 5 hex de SHA-1. Sin botón en la web. |

Las dos últimas rutas se documentan porque son parte de la API, pero la interfaz
no las llama: hacen falta pasos que no aportan a una contraseña buena y
obligarían a enviar la contraseña o su hash fuera de la aplicación. El cálculo
del SHA-1 era además la razón del `sha1.worker.js`, que ya no existe.

Las peticiones entre orígenes llevan la cabecera `X-Passguard-Client: 1`, que
dispara un preflight y por tanto impide que un `fetch` en modo *no-cors* o un
formulario HTML disparen un `POST` desde otra web.

## La política

`policy.py` es el **único** sitio donde vive la política. La interfaz no la
reescribe: la descarga. Eso elimina la divergencia entre servidor y cliente, que
en la versión anterior de este proyecto tenía el umbral de 12 caracteres
escrito en cuatro sitios distintos.

- `upsin-seg-2026-c1`, versión `1.0.0`.
- Longitud de 12 a 128.
- Entropía estimada mínima de 40 bits.
- Escala ordinal de 0 a 4 con etiquetas accionables, con los umbrales derivados
  de los rangos de Log10(guesses) del Apéndice A de NIST SP 800-63B.
- Ataque supuesto: 10<sup>10</sup> intentos por segundo, SHA-256 sin sal, modo
  offline. Es deliberadamente pesimista: asume recursos dedicados.

Hay 11 reglas. Las cinco de composición se mantienen porque la materia las pide,
pero quedan **por debajo** de la entropía y del contraste con el corpus: en la
versión anterior cumplirlas bastaba, y eso aprobaba `aA1!aA1!aA1!aA1!`.

El modelo de ataque importa más que la fórmula. `P4$$w0rd!2024` cumple las cinco
reglas y no está en ningún diccionario de passwords filtrados, pero un atacante
razonador lo genera en milisegundos con la lógica "palabra en español + año en
curso + dos sustituciones". El corpus de este proyecto está construido para que
ese caso se detecte, y por eso la política penaliza los patrones, no solo las
clases de caracteres.

## Modelo de amenazas

Lo que esta aplicación **sí** hace:

- **No guarda la contraseña en ningún sitio.** Ni en el log, ni en la base de
  datos, ni en un fichero. La auditoría registra
  `HMAC-SHA256(clave_de_32_bytes, contraseña)`, con una clave que se genera al
  arrancar el proceso y se pierde al reiniciar. Detectar reutilización no obliga
  a guardar el secreto, que es justamente lo que había que evitar.
- **No filtra el secreto en los logs, ni por accidente.** Una excepción
  inesperada imprime su traza, y la traza incluye el mensaje de la excepción: si
  ese mensaje interpola la contraseña, el secreto quedaba escrito en el log. Aquí
  el traza se formatea a mano, se redacta y se registra como un mensaje normal.
  `tests/test_no_log_leak.py` lo comprueba de verdad, capturando el flujo real.
- **No acepta orígenes ajenos.** El `Origin` se valida en el servidor, no solo
  en la respuesta: CORS protege la lectura de la respuesta, no la ejecución de
  la petición. Un `Origin` fuera de la lista es un 403, y una escritura entre
  orígenes además tiene que declarar `X-Passguard-Client`.
- **No expone el debugger.** `PASSGUARD_DEBUG` sale del entorno y el host por
  defecto es `127.0.0.1`.
- **No acepta cuerpos sin límite.** 8 KiB, y un cuerpo mayor es un 413.
- **No se cuelga con entradas absurdas.** El generador tiene techo de reintentos
  y recorta la longitud al rango válido. El `while True` original pedía 12
  caracteres que él mismo no producía cuando le pedían 5, y cuatro peticiones
  bastaban para dejar el hilo al 100 % de CPU para siempre.
- **No devuelve trazas al cliente.** Ningún error sale como HTML; todos son JSON
  con un código estable.

Lo que **no** hace, y conviene decir en voz alta:

- **No es autenticación.** `X-Passguard-Client` no es un token: es una constante
  pública. Detecta ataques desde navegadores, no scripts. Quien tenga la URL
  puede llamar a la API con curl, y por eso está el límite de peticiones.
- **La contraseña viaja al servidor** durante el análisis, y eso es un compromiso
  real: está expuesta en tránsito, en la memoria del proceso y en sus registros.
  En un sistema de producción, el orden de preferencia sería no mandar la
  contraseña, mandar solo el resultado ya calculado, y solo entonces todo lo
  demás. Aquí es inevitable: el corpus de 3.755 contraseñas comunes y la
  estimación de tiempo de ruptura no se pueden hacer bien en el navegador.
- **El limitador de peticiones vive en memoria.** Con varias instancias o tras un
  reinicio, el contador vuelve a cero. En un despliegue real haría falta Redis.
- **El corpus es pequeño.** 3.755 contraseñas, suficiente para la asignatura y
  lejos de ser un corpus de calidad forense.

## Despliegue

### Frontend: GitHub Pages

`.github/workflows/pages.yml` publica el contenido de `static/` en la raíz del
sitio, de modo que `app.js` y `config.js` quedan en la raíz y no bajo un
subdirectorio.

En `static/config.js` hay una única línea que hay que cambiar tras el primer
despliegue:

```javascript
apiBase: 'https://<cuenta>.pythonanywhere.com'
```

Y una cosa que conviene saber antes de extrañar una diferencia: **el
`index.html` que se publica no es idéntico al del repositorio.** El workflow le
añade `?v=<sha>` a las referencias de `styles.css`, `config.js` y `app.js`.

El motivo es la caché. GitHub Pages responde con `Cache-Control: max-age=600` y
GitHub no permite cambiarlo, así que el navegador guarda esos ficheros diez
minutos. Sin el `?v=`, quien abre la web después de un despliegue puede estar
viendo la versión anterior, y el síntoma es desconcertante: la página anunciaba
"modo local · sin backend" con el backend funcionando y el CORS ya resuelto. El
`?v=` cambia la clave de caché, así que cada despliegue entrega URLs nuevas y la
caché no puede servir nada viejo.

La contrapartida es que la ventana de diez minutos no desaparece del todo,
solo se reduce a un fichero. `index.html` también pasa por la caché y no lleva
`?v=` —no puede, es justamente el que decide cuál le pone a los demás—, así
que quien abra la web dentro de esos diez minutos tras un despliegue todavía
recibe el HTML anterior. En ese caso hace falta un refresco forzado, o esperar,
y a partir de ahí todo entra limpio. Antes el riesgo eran los tres recursos;
ahora es solo el documento que decide cuáles son.

### API: PythonAnywhere

Primero, tener el código en el servidor. En el plan gratuito no hay integración
de Git en el panel, así que se usa la **consola Bash** (pestaña *Consoles*):

```bash
git clone https://github.com/Julpach65/passguard-lab.git ~/passguard-lab
cd ~/passguard-lab
python3 -c "import flask; print(flask.__version__)" || pip install --user "flask>=3.0,<4"
```

El corpus viene en el repositorio, así que no hay que generarlo.

Después, en la pestaña **Web**, *Add a new web app* → framework **Flask** →
dominio `<cuenta>.pythonanywhere.com`, con el directorio de código fijado en
`/home/<cuenta>/passguard-lab`.

1. **WSGI configuration file**: arriba del todo del bloque de la web app está
   el enlace que abre `/var/www/<cuenta>_pythonanywhere_com_wsgi.py`. Seleccionar
   todo su contenido y pegarlo entero. El fichero ya está en el repo, listo para
   copiar, en `deploy/wsgi_pythonanywhere.py`, con el motivo de cada línea
   escrito al lado.

   **Las variables de entorno van en este mismo fichero**, no en un apartado del
   panel: PythonAnywhere no tiene ningún campo para declararlas. Lo único que
   se ejecuta antes de servir algo es el WSGI, así que es el único sitio donde
   el proceso web las ve. Un `export` en la consola Bash funciona en la consola
   y nowhere más, y el fallo clásico es ponerlo ahí, comprobar que la consola sí
   lo ve, y que la web siga devolviendo 403.

   Lo que trae, y por qué no se puede dejar solo `from wsgi import app`:

   ```python
   import os
   import sys

   # Este fichero vive en /var/www/, fuera del proyecto, y PythonAnywhere solo
   # anade su propio directorio a la ruta. Sin esta linea, ModuleNotFoundError.
   path = '/home/<cuenta>/passguard-lab'
   if path not in sys.path:
       sys.path.insert(0, path)

   # Sin la subruta /passguard-lab, porque Origin nunca la lleva.
   os.environ['PASSGUARD_ALLOWED_ORIGINS'] = 'https://julpach65.github.io'

   # PythonAnywhere busca una variable llamada exactamente "application".
   from wsgi import app as application  # noqa: E402
   ```

2. **Reload** en la misma pestaña.

Solo se declara `PASSGUARD_ALLOWED_ORIGINS`. `PASSGUARD_CORPUS_PATH` no hace
falta: su valor por defecto ya resuelve a `<raíz del proyecto>/data/corpus.txt`.
La clave de firma se genera en memoria al arrancar, así que no hay ningún otro
secreto que declarar.

Comprobación desde fuera, que es la que de verdad importa:

```bash
curl -i https://<cuenta>.pythonanywhere.com/api/health
curl -i -X POST https://<cuenta>.pythonanywhere.com/api/analyze \
  -H 'Content-Type: application/json' \
  -H 'Origin: https://julpach65.github.io' \
  -H 'X-Passguard-Client: 1' \
  -d '{"password":"aA1!aA1!aA1!aA1!","context":[]}'
```

Lo que sale de esa última llamada es el punto de la entrega: una contraseña que
cumple las cinco reglas y a la vez el veredicto la rechaza.

`PASSGUARD_DEBUG` no se define: su ausencia ya significa desactivado, y ese es
el valor por defecto a propósito. No hay ninguna variable para la clave de
auditoría porque no debe existir: se genera sola en memoria en cada arranque.

Dos cosas del plan gratuito que conviene tener presentes: **la web app caduca
cada mes y hay que renovarla a mano**, o el enlace del profesor deja de
funcionar a mitad de semestre; y la salida a Internet puede estar limitada según
el plan y el destino, así que la consulta a HIBP puede no llegar. Esa ruta
degrada a `{"available": false}` con un 200 en lugar de romper la interfaz, por
ser un servicio opcional.

## Checklist de entrega

Lo que hay que comprobar, en orden. Los cuatro primeros puntos son el despliegue;
los dos últimos son la prueba de que el despliegue sirve de algo.

- [ ] `pytest -q` en verde sobre el repositorio recién clonado.
- [ ] API en PythonAnywhere con el código en `/home/Julpach65/passguard-lab` y el
      WSGI exportando `application`.
- [ ] Variable `PASSGUARD_ALLOWED_ORIGINS=https://julpach65.github.io` en *Web →
      Edit → Environment variables*, y **Reload** después de añadirla. Sin ella
      el navegador bloquea la respuesta y la web cae en modo local.
- [ ] `apiBase` en `static/config.js` apuntando a
      `https://julpach65.pythonanywhere.com`, y push para que Pages lo sirva.
- [ ] La web app no caduca: en el plan gratuito hay que renovarla a mano. La de
      esta entrega caduca el **28 de octubre de 2026**.
- [ ] `curl` a `/api/health` y a `/api/analyze` con `Origin` y
      `X-Passguard-Client` devolviendo 200 (abajo).
- [ ] Comprobación manual en el navegador, que la suite no puede hacer: con la
      web abierta, escribir una contraseña y ver que la lista de requisitos se
      pinta; y con la API caída, que la página **avise** y no dé nota. Que la
      misma contraseña rejected por el servidor no salga aprobada en local es el
      punto entero del diseño.

## Licencia y autoría

Proyecto de autoría propia, escrito para esta asignatura. No reutiliza código de
ningún otro analizador de contraseñas.
