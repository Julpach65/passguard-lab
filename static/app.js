/* ==========================================================================
   PassGuard Lab - capa de cliente
   --------------------------------------------------------------------------
   Diseno en dos capas, deliberado:

     1. Prevalidacion local, sincrona, en cada tecla. Cero red. Da la sensacion
        de respuesta instantanea aunque el backend este caido.
     2. Veredicto autoritativo del servidor, con debounce de 350 ms y
        AbortController. El servidor manda porque tiene el corpus de 20.000
        contrasenas comunes y la política real; el navegador solo aproxima.

   Cuando la capa 2 falla, se conserva la capa 1 y se dice con claridad. Es
   preferible una estimacion honestamente marcada como local a un error.
   ========================================================================== */

'use strict';

(function () {
  /* ---------------------------------------------------------------- config */

  const CFG = window.PASSGUARD_CONFIG || {};

  const IS_FILE = window.location.protocol === 'file:';
  const API_BASE = typeof CFG.apiBase === 'string' ? CFG.apiBase.trim().replace(/\/+$/, '') : '';
  // Sin apiBase y abriendo el archivo con file:// no existe origen: se quedará
  // en modo local. Con file:// y apiBase puesto, si se permitiera, el fetch a
  // un origen https desde un origen null se bloquearía por CORS.
  const BASE = API_BASE || (IS_FILE ? '' : window.location.origin);
  // Se aceptan las dos grafías: la corregida y la que venía en el enunciado.
  const HIBP_ENABLED = CFG.hibpEnabled !== undefined ? CFG.hibpEnabled !== false : CFG.hibrEnabled !== false;

  const CLIENT_HEADER = 'X-Passguard-Client';
  const CLIENT_VALUE = '1';

  const DEBOUNCE_ANALYZE = 350;
  const DEBOUNCE_HIBP = 500;
  const DEBOUNCE_VERDICT = 700;
  const TIMEOUT_DEFAULT = 8000;
  const TIMEOUT_HEALTH = 4000;
  const ATTACKS_PER_SECOND = 1e10;
  const LOG10_2 = Math.log10(2);
  const VISIBLE_MAX = 64;

  /* ------------------------------------------------------- acceso al DOM */

  // Única fuente de verdad de los ids que el JS necesita. La comprobación de
  // abajo avisa en consola si el HTML y este archivo se desincronizan, que es
  // el fallo más habitual al tocar este proyecto. Es el único uso de consola.
  const E = {};
  const MISSING = [];
  function bind(ids) {
    ids.forEach((id) => {
      const node = document.getElementById(id);
      if (node) {
        E[id] = node;
      } else {
        MISSING.push(id);
      }
    });
  }

  bind([
    // cabecera
    'status-badge', 'status-dot', 'status-text', 'btn-recheck', 'policy-version', 'policy-corpus',
    // analizador
    'panel-analizador', 'pw-input', 'pw-input-wrap', 'btn-toggle-pw', 'btn-clear-pw', 'pw-hint',
    'pw-meter', 'strength-score', 'strength-label', 'analyze-status', 'strength-fill', 'verdict-live',
    'notice-fallback', 'fallback-detail', 'btn-retry', 'requirements-list',
    'metric-entropy', 'metric-charset', 'metric-guesses', 'metric-cracktime', 'metric-valid', 'metric-source',
    'findings-list', 'explanation-text',
    // hibrido
    'hibp-panel', 'hibp-state', 'hibp-count',
    // auditoria
    'btn-audit', 'audit-status', 'audit-receipt',
    // generador
    'panel-generador', 'gen-form', 'gen-length', 'gen-length-value', 'gen-len-bounds', 'gen-alphabet',
    'gen-use-lower', 'gen-use-upper', 'gen-use-digits', 'gen-use-symbols',
    'gen-min-classes', 'gen-avoid-ambiguous', 'gen-submit', 'btn-gen-analyze',
    'gen-output', 'btn-gen-copy', 'gen-status', 'gen-entropy', 'gen-alphabet-size', 'gen-classes',
    'gen-policy', 'gen-analysis'
  ]);

  if (MISSING.length) {
    console.warn('PassGuard: ids ausentes en index.html ->', MISSING.join(', '));
  }

  /* ------------------------------------------------------------- útileria */

  const str = (v, fallback) => (typeof v === 'string' ? v : (fallback === undefined ? '' : fallback));
  // Coacciona strings a proposito: el .value de un input o un select es siempre
  // texto. Con una comprobación estricta de tipo, el slider de longitud se
  // leeria siempre como su valor por defecto y el control pareceria muerto.
  const num = (v, fallback) => {
    const n = typeof v === 'number' ? v : parseFloat(v);
    return Number.isFinite(n) ? n : (fallback === undefined ? 0 : fallback);
  };
  const arr = (v) => (Array.isArray(v) ? v : []);
  const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
  const round = (v, d) => {
    const f = Math.pow(10, d);
    return Math.round(v * f) / f;
  };

  const NO_METRIC = '\u2014';
  const GLYPH_OK = '\u2713';
  const GLYPH_NO = '\u2717';

  /* ------------------------------------------------------- capa HTTP */

  class ApiError extends Error {
    constructor(code, message, status) {
      super(message || code || 'error');
      this.name = 'ApiError';
      this.code = code || 'internal_error';
      this.status = status || 0;
    }
  }

  function abortedError() {
    const err = new Error('petición cancelada');
    err.name = 'AbortError';
    return err;
  }

  const isAbort = (err) => Boolean(err) && (err.name === 'AbortError' || err.superseded === true);
  const isTimeout = (err) => Boolean(err) && err.name === 'TimeoutError';

  // Única función de red. Centraliza tres cosas que no se pueden dejar al
  // azar: la cabecera que obliga al preflight CORS, el timeout y el hecho de
  // que response.ok se compruebe SIEMPRE antes de tocar el JSON.
  async function request(path, options) {
    const opt = options || {};
    const method = opt.method || 'GET';
    const timeout = typeof opt.timeout === 'number' ? opt.timeout : TIMEOUT_DEFAULT;
    const external = opt.signal || null;

    if (!BASE) {
      throw new ApiError('api_unavailable', 'Sin backend configurado: revisa apiBase en config.js.');
    }
    if (external && external.aborted) throw abortedError();

    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeout);

    const relay = () => controller.abort();
    if (external) external.addEventListener('abort', relay, { once: true });

    const headers = { Accept: 'application/json' };
    if (method !== 'GET') {
      headers['Content-Type'] = 'application/json';
      // Esta cabecera es la que dispara el preflight: un formulario o un
      // <img> desde otra pagina no pueden ponerla, asi que el backend recibe
      // una petición que solo puede venir de este cliente consentido.
      headers[CLIENT_HEADER] = CLIENT_VALUE;
    }

    let response;
    try {
      response = await fetch(BASE + path, {
        method: method,
        headers: headers,
        body: method === 'GET' ? undefined : JSON.stringify(opt.body || {}),
        signal: controller.signal,
        mode: 'cors',
        credentials: 'omit',
        cache: 'no-store',
        referrerPolicy: 'no-referrer'
      });
    } catch (err) {
      if (timedOut) {
        const e = new ApiError('api_unavailable', 'El servidor no respondió en ' + timeout + ' ms.');
        e.name = 'TimeoutError';
        throw e;
      }
      if (isAbort(err)) {
        const e = abortedError();
        e.superseded = true;
        throw e;
      }
      throw new ApiError('api_unavailable', 'No hay conexión con ' + BASE + '.');
    } finally {
      clearTimeout(timer);
      if (external) external.removeEventListener('abort', relay);
    }

    // El cuerpo se lee como texto y se parsea a mano: un HTML de error de un
    // proxy delante del backend no debe romper el flujo con un SyntaxError.
    let raw = '';
    try {
      raw = await response.text();
    } catch (err) {
      if (isAbort(err)) {
        const e = abortedError();
        e.superseded = true;
        throw e;
      }
      throw new ApiError('internal_error', 'No se pudo leer la respuesta.', response.status);
    }

    let json = null;
    if (raw) {
      try {
        json = JSON.parse(raw);
      } catch (err) {
        json = null;
      }
    }

    if (!response.ok) {
      const info = json && json.error ? json.error : null;
      const err = new ApiError(str(info && info.code, 'internal_error'), str(info && info.message, 'Error ' + response.status), response.status);
      if (timedOut) err.name = 'TimeoutError';
      throw err;
    }

    if (json === null || typeof json !== 'object') {
      throw new ApiError('internal_error', 'La respuesta del servidor no es JSON valido.', response.status);
    }
    return json;
  }

  const api = {
    health: (options) => request('/api/health', Object.assign({ timeout: TIMEOUT_HEALTH }, options)),
    policy: (options) => request('/api/policy', options),
    analyze: (payload, options) => request('/api/analyze', Object.assign({ method: 'POST', body: payload }, options)),
    generate: (payload, options) => request('/api/generate', Object.assign({ method: 'POST', body: payload }, options)),
    audit: (payload, options) => request('/api/audit', Object.assign({ method: 'POST', body: payload }, options)),
    hibp: (prefix, options) => request('/api/hibp', Object.assign({ method: 'POST', body: { prefix: prefix } }, options))
  };
  /* ------------------------------------------------------------- política */

  // Espejo de policy.py. Solo entra en juego si GET /api/policy no responde,
  // para que abriendo el HTML con file:// la aplicación siga siendo utilizable.
  // En cuanto el servidor responde, este objeto se descarta: los labels de los
  // requisitos no están duplicados en el DOM que dibuja la lista.
  const FALLBACK_POLICY = {
    policy_id: 'upsin-seg-2026-c1',
    version: '1.0.0',
    min_length: 12,
    max_length: 128,
    min_entropy_bits: 40,
    attacks_per_second: ATTACKS_PER_SECOND,
    attack_hash: 'SHA-256 sin sal, ataque offline',
    corpus: { name: 'common-passwordes-es', size: 0, loaded: false },
    rules: [
      { id: 'length', label: 'Mínimo 12 caracteres', kind: 'min_length', value: 12 },
      { id: 'uppercase', label: 'Al menos una mayúscula', kind: 'character_class', value: 'uppercase' },
      { id: 'lowercase', label: 'Al menos una minúscula', kind: 'character_class', value: 'lowercase' },
      { id: 'number', label: 'Al menos un número', kind: 'character_class', value: 'number' },
      { id: 'symbol', label: 'Al menos un símbolo', kind: 'character_class', value: 'symbol' },
      { id: 'not_common', label: 'No aparece en el diccionario de contraseñas comunes', kind: 'corpus', value: null },
      { id: 'no_sequence', label: 'Sin secuencias ascendentes o descendentes', kind: 'pattern', value: 'sequence' },
      { id: 'no_keyboard', label: 'Sin recorridos de teclado contiguos', kind: 'pattern', value: 'keyboard' },
      { id: 'no_repeat', label: 'Sin caracteres o bloques repetidos', kind: 'pattern', value: 'repeat' },
      { id: 'no_date', label: 'Sin años ni fechas recientes', kind: 'pattern', value: 'date' },
      { id: 'entropy', label: 'Al menos 40 bits estimados', kind: 'min_bits', value: 40 }
    ],
    scores: [
      { level: 0, min_bits: 0, label: 'Muy débil', color: '#EF4444' },
      { level: 1, min_bits: 28, label: 'Débil', color: '#F59E0B' },
      { level: 2, min_bits: 44, label: 'Aceptable', color: '#EAB308' },
      { level: 3, min_bits: 60, label: 'Fuerte', color: '#22C55E' },
      { level: 4, min_bits: 80, label: 'Muy fuerte', color: '#00FF41' }
    ],
    fromServer: false
  };

  // Valida la forma antes de confiar. Si el servidor devolviera otra cosa, se
  // ignora en lugar de propagar undefined por toda la interfaz.
  function normalizePolicy(raw) {
    if (!raw || typeof raw !== 'object') return null;
    const rules = arr(raw.rules).filter((r) => r && typeof r.id === 'string' && typeof r.label === 'string');
    const scores = arr(raw.scores)
      .filter((s) => s && num(s.min_bits) >= 0)
      .map((s) => ({
        level: num(s.level),
        min_bits: num(s.min_bits),
        label: str(s.label, 'nivel'),
        color: str(s.color, '#8B949E')
      }))
      .sort((a, b) => a.min_bits - b.min_bits);
    if (!rules.length || !scores.length) return null;

    const attack = raw.attack_assumption && typeof raw.attack_assumption === 'object' ? raw.attack_assumption : {};
    return {
      policy_id: str(raw.policy_id, 'desconocida'),
      version: str(raw.version, '-'),
      min_length: clamp(num(raw.min_length, 12), 1, 512),
      max_length: clamp(num(raw.max_length, 128), 1, 512),
      min_entropy_bits: num(raw.min_entropy_bits, 40),
      attacks_per_second: num(attack.attempts_per_second, ATTACKS_PER_SECOND) || ATTACKS_PER_SECOND,
      attack_hash: str(attack.hash, 'SHA-256 sin sal, ataque offline'),
      corpus: raw.corpus && typeof raw.corpus === 'object'
        ? { name: str(raw.corpus.name, 'desconocido'), size: num(raw.corpus.size, 0), loaded: raw.corpus.loaded === true }
        : { name: 'desconocido', size: 0, loaded: false },
      rules: rules,
      scores: scores,
      fromServer: true
    };
  }

  let POLICY = FALLBACK_POLICY;

  function scoreForBits(bits) {
    let selected = POLICY.scores[0];
    POLICY.scores.forEach((entry) => {
      if (bits >= entry.min_bits) selected = entry;
    });
    return selected;
  }

  /* -------------------------------------------------- detectores locales */

  // Subconjunto reducido del corpus del servidor. No pretende sustituirlo: sirve
  // para marcar en rojo de entrada lo que es de manual un diccionario, y el
  // veredicto definitivo lo da el servidor con sus 20.000 entradas.
  const COMMON_LIST = [
    '123456', 'password', '123456789', '12345678', '12345', 'qwerty', 'abc123', '111111', '123123',
    '1234567890', 'contrasena', 'contrasen', 'admin', 'administrador', 'usuario', 'usuario123',
    'colombia', 'colombiano', 'upsin', 'sincelejo', 'cordoba', 'bogota', 'medellin', 'cali', 'pereira',
    'barranquilla', 'cartagena', 'cucuta', 'bucaramanga', 'carnaval', 'verano', 'invierno', 'navidad',
    'mama', 'papa', 'amor', 'familia', 'cristiano', 'dios', 'jesus', 'sagrada', 'casa', 'perro',
    'gato', 'futbol', 'america', 'million', 'milagros', 'sexy', 'bella', 'chica',
    'estrella', 'princesa', 'dragon', 'master', 'monkey', 'shadow', 'sunshine', 'superman', 'batman',
    'michael', 'juan', 'juanito', 'juanp', 'carlos', 'carlitos', 'maria', 'mariana', 'marianela', 'sofia',
    'laura', 'laurita', 'andrea', 'alejandra', 'sandra', 'sandro', 'luis', 'luisa', 'pedro', 'pedrito',
    'david', 'daniel', 'jorge', 'ana', 'anita', 'la', 'el', 'de', 'yo', 'mi', 'tu', 'se',
    'qwert', 'asdfgh', 'zxcvbn', 'qwerty123', 'abc', 'abcd1234', 'iloveyou', 'princess', 'rockyou',
    '111222', '000000', '654321', '987654321', '123321', '1q2w3e4r', '1qaz2wsx', 'qazwsx', 'asdf1234',
    'password1', 'password123', 'contrasena123', 'hola123', 'hola', 'prueba', 'prueba123', 'temporal',
    'cambio', 'nuevo', 'nueva', 'inicial', 'primero', 'admin123', 'root', 'toor'
  ];
  const COMMON_RANK = new Map();
  COMMON_LIST.forEach((pw, i) => {
    if (!COMMON_RANK.has(pw)) COMMON_RANK.set(pw, i + 1);
  });

  // Ataque por diccionario real: no hace falta que la contraseña SEA la palabra,
  // basta con que la palabra este dentro. "P4$$w0rd!2024" es "password" + "2024",
  // y un cracker de verdad la encuentra en segundos. Se exige un m de 5
  // letras para no disparar falsas alarma con fragmentos cortos.
  function findDictionaryHit(letters) {
    let best = null;
    COMMON_RANK.forEach((rank, word) => {
      if (word.length >= 5 && letters.indexOf(word) >= 0) {
        if (!best || word.length > best.word.length) best = { word: word, rank: rank };
      }
    });
    return best;
  }

  const L33T = {
    '4': 'a', '@': 'a', '8': 'b', '6': 'g', '9': 'g', '3': 'e', '1': 'l', '!': 'i', '0': 'o',
    '$': 's', '5': 's', '7': 't', '+': 't', '2': 'z', '(': 'c', '|': 'l'
  };
  function del33t(password) {
    let out = '';
    for (const ch of password.toLowerCase()) out += L33T[ch] || ch;
    return out;
  }

  function findSequence(password) {
    const s = password.toLowerCase();
    let run = 1;
    for (let i = 1; i < s.length; i += 1) {
      const diff = s.charCodeAt(i) - s.charCodeAt(i - 1);
      if (diff === 1 || diff === -1) {
        run += 1;
        if (run >= 4) return s.slice(i - run + 1, i + 1);
      } else {
        run = 1;
      }
    }
    return null;
  }

  const KEYBOARD_SET = (function buildKeyboardSet() {
    const rows = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890', '1qaz2wsx3edc', 'zaq12wsx'];
    const set = new Set();
    rows.forEach((row) => {
      set.add(row);
      set.add(row.split('').reverse().join(''));
    });
    return set;
  }());

  function findKeyboard(password) {
    const s = password.toLowerCase();
    const max = Math.min(6, s.length);
    for (let n = 4; n <= max; n += 1) {
      for (let i = 0; i + n <= s.length; i += 1) {
        const seg = s.slice(i, i + n);
        if (KEYBOARD_SET.has(seg)) return seg;
      }
    }
    return null;
  }

  function findRepeat(password) {
    const sameChar = password.match(/(.)\1{2,}/);
    if (sameChar) return sameChar[0];
    const sameBlock = password.match(/(.{2,4})\1+/);
    if (sameBlock) return sameBlock[0];
    return null;
  }

  const MONTHS = 'enero|febrero|marzo|abril|mayo|junio|julio|agosto|septiembre|setiembre|octubre|noviembre|diciembre';
  function findDate(password) {
    const year = password.match(/(19|20)\d{2}/);
    if (year) return year[0];
    const full = password.match(/\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}/);
    if (full) return full[0];
    const name = password.match(new RegExp(MONTHS, 'i'));
    if (name) return name[0];
    return null;
  }

  function charsetOf(password) {
    let n = 0;
    if (/[a-z]/.test(password)) n += 26;
    if (/[A-Z]/.test(password)) n += 26;
    if (/[0-9]/.test(password)) n += 10;
    const others = new Set();
    for (const ch of password) {
      if (!/[a-zA-Z0-9]/.test(ch) && ch !== ' ') others.add(ch);
    }
    n += others.size;
    if (password.indexOf(' ') >= 0) n += 1;
    return Math.max(n, 1);
  }

  function classCountOf(password) {
    let n = 0;
    if (/[a-z]/.test(password)) n += 1;
    if (/[A-Z]/.test(password)) n += 1;
    if (/[0-9]/.test(password)) n += 1;
    if (/[^a-zA-Z0-9\s]/.test(password)) n += 1;
    return n;
  }

  // Solo primer y último carácter: orienta al usuario sin destripar la
  // contraseña en una pantalla compartida o en una captura de pantalla.
  function maskOf(password, tag) {
    if (password.length <= 2) return '[' + tag + ']';
    return password[0] + '[' + tag + ']' + password[password.length - 1];
  }

  function humanDuration(seconds) {
    if (!Number.isFinite(seconds) || seconds < 0) return 'indeterminado';
    if (seconds < 1) return 'menos de un segundo';
    if (seconds < 60) {
      const v = Math.round(seconds);
      return v === 1 ? '1 segundo' : v + ' segundos';
    }
    if (seconds < 3600) {
      const v = Math.round(seconds / 60);
      return v === 1 ? '1 minuto' : v + ' minutos';
    }
    if (seconds < 86400) {
      const v = Math.round(seconds / 3600);
      return v === 1 ? '1 hora' : v + ' horas';
    }
    if (seconds < 2592000) {
      const v = Math.round(seconds / 86400);
      return v === 1 ? '1 día' : v + ' días';
    }
    if (seconds < 31536000) {
      const v = Math.round(seconds / 2592000);
      return v === 1 ? '1 mes' : v + ' meses';
    }
    const years = seconds / 31536000;
    if (years < 1e3) return Math.round(years) + ' años';
    if (years < 1e6) return round(years / 1e3, 1) + ' mil años';
    if (years < 1e9) return round(years / 1e6, 1) + ' millones de años';
    if (years < 1e12) return round(years / 1e9, 1) + ' mil millones de años';
    return '10^' + Math.floor(Math.log10(years)) + ' años';
  }
  /* ------------------------------------------------- analizador local */

  // Devuelve exactamente la misma forma que /api/analyze. Esa es la decision que
  // sostiene el diseño: un único renderizador para las dos capas, de modo que el
  // fallback no necesita una segunda ruta de c ni puede divergir.
  function analyzeLocally(password) {
    const p = POLICY;
    const len = password.length;
    const charset = charsetOf(password);
    const lower = password.toLowerCase();
    const unleet = del33t(password);
    const findings = [];

    // Diccionario: coincidencia exacta o el patron "palabra + a\ufff1o", que es
    // la forma más extendida de construir contraseñas "robustas".
    let rank = COMMON_RANK.get(lower) || COMMON_RANK.get(unleet) || 0;
    let dictionaryWord = COMMON_RANK.has(lower) ? lower : unleet;
    if (!rank) {
      const shaped = password.match(/^([^0-9!@#$%^&*]{4,})(\d{1,4})([!@#$%^&*]?)$/);
      if (shaped) {
        const wordRank = COMMON_RANK.get(shaped[1].toLowerCase()) || COMMON_RANK.get(del33t(shaped[1]));
        if (wordRank) {
          rank = wordRank + 200;
          dictionaryWord = shaped[1].toLowerCase();
        }
      }
    }
    if (!rank) {
      const hit = findDictionaryHit(unleet.replace(/[^a-z]/g, ''));
      if (hit) {
        rank = hit.rank;
        dictionaryWord = hit.word;
      }
    }
    if (rank) {
      findings.push({
        id: 'dictionary',
        severity: 'critical',
        label: 'Aparece entre las contraseñas más usadas',
        detail: 'contiene "' + dictionaryWord + '", posición aproximada ' + rank + ' en el subconjunto local',
        masked: maskOf(password, 'diccionario')
      });
    }

    const sequence = findSequence(password);
    if (sequence) {
      findings.push({
        id: 'sequence',
        severity: 'high',
        label: 'Contiene una secuencia',
        detail: "'" + sequence + "'",
        masked: maskOf(password, 'secuencia')
      });
    }

    const keyboard = findKeyboard(password);
    if (keyboard) {
      findings.push({
        id: 'keyboard',
        severity: 'high',
        label: 'Contiene un recorrido de teclado contiguo',
        detail: "'" + keyboard + "'",
        masked: maskOf(password, 'teclado')
      });
    }

    const repeat = findRepeat(password);
    if (repeat) {
      findings.push({
        id: 'repeat',
        severity: 'medium',
        label: 'Contiene caracteres o bloques repetidos',
        detail: "'" + repeat + "'",
        masked: maskOf(password, 'repeticion')
      });
    }

    const date = findDate(password);
    if (date) {
      findings.push({
        id: 'date',
        severity: 'medium',
        label: 'Contiene un año o una fecha',
        detail: "'" + date + "'",
        masked: maskOf(password, 'fecha')
      });
    }

    if (unleet !== lower && /[0-9@$!+7]/.test(password)) {
      findings.push({
        id: 'l33t',
        severity: 'low',
        label: 'Usa sustituciones de tipo l33t',
        detail: 'al reducirla queda "' + unleet + '"',
        masked: maskOf(password, 'l33t')
      });
    }

    if (len < p.min_length) {
      findings.push({
        id: 'short',
        severity: 'high',
        label: 'Menos de ' + p.min_length + ' caracteres',
        detail: len + ' de ' + p.min_length,
        masked: maskOf(password, 'corta')
      });
    }

    if (charset < 20) {
      findings.push({
        id: 'charset',
        severity: 'info',
        label: 'Alfabeto reducido',
        detail: 'solo ' + charset + ' símbolos distintos',
        masked: maskOf(password, 'alfabeto')
      });
    }

    // Los patrones no restan bits de forma lineal: recortan el espacio de
    // búsqueda. Un factor de 0,45 significa que el atacante prueba menos de la
    // mitad de candidatos, así que se multiplica en lugar de restar.
    let penalty = 1;
    if (rank) penalty *= 0.02;
    if (len < p.min_length) penalty *= 0.5;
    if (sequence) penalty *= 0.45;
    if (keyboard) penalty *= 0.6;
    if (repeat) penalty *= 0.55;
    if (date) penalty *= 0.75;
    if (unleet !== lower) penalty *= 0.8;
    if (charset < 20) penalty *= 0.9;

    const naiveBits = len * Math.log2(charset);
    const guessesLog10 = Math.max(0.3, naiveBits * LOG10_2 * penalty);
    const effectiveBits = guessesLog10 / LOG10_2;
    const seconds = Math.pow(10, guessesLog10) / p.attacks_per_second;
    const score = scoreForBits(effectiveBits);

    const checks = {
      length: len >= p.min_length,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      number: /[0-9]/.test(password),
      symbol: /[^a-zA-Z0-9]/.test(password),
      not_common: !rank,
      no_sequence: !sequence,
      no_keyboard: !keyboard,
      no_repeat: !repeat,
      no_date: !date,
      entropy: effectiveBits >= p.min_entropy_bits
    };

    const missing = p.rules.filter((rule) => checks[rule.id] === false).map((rule) => rule.label);
    const valid = missing.length === 0;

    return {
      password_length: len,
      policy_id: p.policy_id,
      policy_version: p.version,
      valid: valid,
      checks: checks,
      missing: missing,
      score: num(score.level),
      score_label: str(score.label, 'nivel ' + score.level),
      score_color: str(score.color, '#8B949E'),
      entropy_bits: round(effectiveBits, 1),
      charset_size: charset,
      classes_present: classCountOf(password),
      guesses_log10: round(guessesLog10, 1),
      crack_time: { seconds: seconds, human: humanDuration(seconds), attempts_per_second: p.attacks_per_second },
      findings: findings,
      explanation: explainLocally(len, effectiveBits, score, missing.length, findings, p),
      source: 'local'
    };
  }

  function explainLocally(len, bits, score, missingCount, findings, p) {
    const head = missingCount === 0
      ? 'Cumple los ' + p.rules.length + ' requisitos de la política ' + p.policy_id + '.'
      : 'No cumple la política ' + p.policy_id + ', le faltan ' + missingCount + ' requisitos.';
    const body = ' Con ' + len + ' caracteres y ' + round(bits, 1) + ' bits utiles se situa en el nivel ' +
      num(score.level) + ' (' + str(score.label) + '), suponiendo ' +
      (num(p.attacks_per_second) / 1e9) + ' mil millones de intentos por segundo.';
    if (!findings.length) return head + body + ' No se detecta ningún patón predecible.';
    return head + body + ' El hallazgo más grave es: ' + str(findings[0].label).toLowerCase() + '.';
  }

  /* ----------------------------------------------------- renderizado */

  const REQ_NODES = new Map();

  function buildRequirements() {
    const list = E['requirements-list'];
    if (!list) return;
    list.textContent = '';
    REQ_NODES.clear();
    POLICY.rules.forEach((rule) => {
      const li = document.createElement('li');
      li.className = 'req-item';
      li.setAttribute('role', 'checkbox');
      li.setAttribute('aria-checked', 'false');
      li.dataset.checked = 'false';
      li.dataset.rule = rule.id;

      const glyph = document.createElement('span');
      glyph.className = 'req-glyph';
      glyph.setAttribute('aria-hidden', 'true');
      glyph.textContent = GLYPH_NO;

      const text = document.createElement('span');
      text.className = 'req-text';
      text.textContent = str(rule.label, rule.id);

      li.appendChild(glyph);
      li.appendChild(text);
      list.appendChild(li);
      REQ_NODES.set(rule.id, { li: li, glyph: glyph, text: text, rule: rule });
    });
  }

  // Anade el valor actual a las dos reglas numericas. El texto "actual: 16
  // caracteres" es lo que convierte un requisito estático en información útil.
  function requirementNote(entry, result) {
    let note = entry.li.querySelector('.req-note');
    if (!note) {
      note = document.createElement('span');
      note.className = 'req-note';
      entry.text.appendChild(note);
    }
    if (entry.rule.kind === 'min_length') {
      note.textContent = 'actual: ' + num(result && result.password_length) + ' caracteres';
    } else if (entry.rule.kind === 'min_bits') {
      note.textContent = 'actual: ' + num(result && result.entropy_bits, 0) + ' bits';
    }
  }

  function paintRequirements(result) {
    const checks = (result && result.checks) || {};
    REQ_NODES.forEach((entry, id) => {
      const pass = checks[id] === true;
      entry.li.setAttribute('aria-checked', pass ? 'true' : 'false');
      entry.li.dataset.checked = pass ? 'true' : 'false';
      entry.glyph.textContent = pass ? GLYPH_OK : GLYPH_NO;
      // El glifo lleva aria-hidden para no duplicarse, y el <li> compone su
      // propio nombre accesible: nunca dependemos solo del color.
      entry.li.setAttribute('aria-label', (pass ? 'Cumple: ' : 'No cumple: ') + str(entry.rule.label, id));
      if (entry.rule.kind === 'min_length' || entry.rule.kind === 'min_bits') {
        requirementNote(entry, result);
      }
    });
  }

  function setText(id, value) {
    const node = E[id];
    if (node) node.textContent = value;
  }

  function renderMeter(result) {
    const level = clamp(num(result && result.score), 0, 4);
    const color = str(result && result.score_color, '#8B949E');
    const badge = E['strength-score'];
    if (badge) {
      badge.textContent = result ? String(level) : '\u2013';
      badge.style.color = color;
      badge.style.borderColor = color;
    }
    setText('strength-label', result ? str(result.score_label, '') : 'Sin contraseña');
    const fill = E['strength-fill'];
    if (fill) {
      fill.style.width = (result ? (level / 4) * 100 : 0) + '%';
      fill.style.background = color;
    }
  }

  function renderMetrics(result) {
    if (!result) {
      ['metric-entropy', 'metric-charset', 'metric-guesses', 'metric-cracktime', 'metric-valid', 'metric-source']
        .forEach((id) => setText(id, NO_METRIC));
      return;
    }
    setText('metric-entropy', num(result.entropy_bits, 0) + ' bits');
    setText('metric-charset', num(result.charset_size) + ' símbolos');
    setText('metric-guesses', '10^' + num(result.guesses_log10, 0));
    const crack = result.crack_time && typeof result.crack_time === 'object' ? result.crack_time : null;
    setText('metric-cracktime', crack ? str(crack.human, NO_METRIC) : NO_METRIC);
    setText('metric-valid', result.valid === true ? 'si' : 'no');
    setText('metric-source', result.source === 'server' ? 'servidor' : 'navegador');
  }

  const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const severityRank = (value) => {
    const rank = SEVERITY_ORDER[str(value)];
    return rank === undefined ? 9 : rank;
  };

  function renderFindings(findings) {
    const list = E['findings-list'];
    if (!list) return;
    list.textContent = '';
    const items = arr(findings)
      .filter((f) => f && typeof f === 'object')
      .sort((a, b) => severityRank(a.severity) - severityRank(b.severity));

    if (!items.length) {
      const li = document.createElement('li');
      li.className = 'empty-note';
      li.textContent = 'Sin hallazgos: no se detectan patrones predecibles.';
      list.appendChild(li);
      return;
    }

    items.forEach((finding) => {
      const li = document.createElement('li');
      li.className = 'finding';
      li.dataset.severity = str(finding.severity, 'info');

      const badge = document.createElement('span');
      badge.className = 'finding-badge';
      badge.textContent = str(finding.severity, 'info');

      const label = document.createElement('span');
      label.className = 'finding-label';
      label.textContent = str(finding.label, str(finding.id, 'hallazgo'));

      li.appendChild(badge);
      li.appendChild(label);

      const detail = str(finding.detail, '');
      const masked = str(finding.masked, '');
      if (detail || masked) {
        const sub = document.createElement('span');
        sub.className = 'finding-detail';
        sub.textContent = (detail ? detail + ' ' : '') + (masked ? '(' + masked + ')' : '');
        li.appendChild(sub);
      }
      list.appendChild(li);
    });
  }

  // Nota de HIBP que se anexa al resumen en lugar de abrir una segunda region
  // aria-live: asi el usuario de lector de pantalla recibe el dato sin que la
  // pagina tenga dos anuncios compitiendo.
  const HIBP_NOTE = { text: '' };

  function renderAll(result) {
    renderMeter(result);
    paintRequirements(result);
    renderMetrics(result);
    renderFindings(arr(result && result.findings));
    setText('explanation-text', result ? str(result.explanation, '') : 'Escribe una contraseña para ver el análisis.');
    scheduleVerdict(result);
  }

  // Única region aria-live de la pagina. Se actualiza con debounce porque
  // reescribirla en cada pulsacion haria que el lector de pantalla interrumpiera
  // al usuario mientras escribe.
  let verdictTimer = 0;
  function scheduleVerdict(result) {
    if (verdictTimer) clearTimeout(verdictTimer);
    verdictTimer = setTimeout(() => {
      verdictTimer = 0;
      const node = E['verdict-live'];
      if (!node) return;
      if (!result) {
        node.textContent = 'Sin contraseña que analizar.';
        return;
      }
      const parts = [
        str(result.score_label, 'nivel ' + num(result.score)) + ', nivel ' + num(result.score) + ' de 4',
        num(result.entropy_bits, 0) + ' bits estimados',
        result.valid === true ? 'cumple la política' : 'no cumple la política',
        str(result.source) === 'server' ? 'según el servidor' : 'estimación local'
      ];
      node.textContent = parts.join('. ') + '.' + (HIBP_NOTE.text ? ' ' + HIBP_NOTE.text : '');
    }, DEBOUNCE_VERDICT);
  }
  /* ------------------------------------------------------ estado global */

  let currentResult = null;
  let lastAnalyzed = '';

  function setConnState(state, text) {
    const badge = E['status-badge'];
    if (badge) badge.dataset.state = state;
    setText('status-text', text);
  }

  function applyPolicy(policy) {
    POLICY = policy;
    buildRequirements();

    const input = E['pw-input'];
    if (input) input.maxLength = POLICY.max_length;

    const slider = E['gen-length'];
    const lo = POLICY.min_length;
    const hi = Math.max(lo, Math.min(VISIBLE_MAX, POLICY.max_length));
    if (slider) {
      slider.min = String(lo);
      slider.max = String(hi);
      if (num(slider.value) < lo) slider.value = String(lo);
      if (num(slider.value) > hi) slider.value = String(hi);
    }
    const value = E['gen-length-value'];
    if (value && slider) value.textContent = String(clamp(num(slider.value, lo), lo, hi));
    setText('gen-len-bounds', 'Rango ' + lo + '\u2013' + hi + '. La política admite hasta ' + POLICY.max_length + ' caracteres.');

    setText('policy-version', POLICY.policy_id + ' \u00b7 v' + POLICY.version + (POLICY.fromServer ? '' : ' \u00b7 local'));
    setText('policy-corpus', POLICY.corpus.name + (POLICY.corpus.loaded
      ? ' \u00b7 ' + POLICY.corpus.size.toLocaleString('es-CO') + ' entradas'
      : ' \u00b7 no cargado'));
  }

  /* ------------------------------------------------- flujo de an */

  function setPending(pending) {
    const meter = E['pw-meter'];
    if (meter) meter.setAttribute('aria-busy', pending ? 'true' : 'false');
    const status = E['analyze-status'];
    if (status) status.dataset.state = pending ? 'pending' : 'idle';
  }

  // Normaliza la respuesta del servidor contra la forma que espera el
  // renderizador. Los campos que falten se heredan del an local, de modo
  // que un backend con una versión anterior sigue siendo utilizable.
  function normalizeAnalyze(raw, password) {
    const base = analyzeLocally(password);
    const serverChecks = raw && typeof raw.checks === 'object' && raw.checks ? raw.checks : {};
    const checks = {};
    POLICY.rules.forEach((rule) => {
      checks[rule.id] = serverChecks[rule.id] === true;
    });

    const level = clamp(num(raw.score, base.score), 0, 4);
    const byLevel = POLICY.scores.filter((s) => s.level === level)[0];
    const crack = raw.crack_time && typeof raw.crack_time === 'object' ? raw.crack_time : null;

    return {
      password_length: num(raw.password_length, base.password_length),
      valid: raw.valid === true,
      checks: checks,
      missing: arr(raw.missing).filter((m) => typeof m === 'string'),
      score: level,
      score_label: str(raw.score_label, str(byLevel && byLevel.label, base.score_label)),
      score_color: str(raw.score_color, str(byLevel && byLevel.color, base.score_color)),
      entropy_bits: num(raw.entropy_bits, base.entropy_bits),
      charset_size: num(raw.charset_size, base.charset_size),
      guesses_log10: num(raw.guesses_log10, base.guesses_log10),
      crack_time: {
        seconds: num(crack && crack.seconds, base.crack_time.seconds),
        human: str(crack && crack.human, base.crack_time.human),
        attempts_per_second: num(crack && crack.attempts_per_second, base.crack_time.attempts_per_second)
      },
      findings: arr(raw.findings).filter((f) => f && typeof f === 'object'),
      explanation: str(raw.explanation, base.explanation),
      source: 'server'
    };
  }

  function showFallback(err) {
    const notice = E['notice-fallback'];
    if (notice) notice.hidden = false;
    const detail = E['fallback-detail'];
    if (detail) {
      detail.textContent = 'Mostramos la estimación del navegador: longitud, clases de caracteres, entropía por ' +
        'alfabeto y los patrones más comunes. Motivo: ' + str(err && err.message, 'error desconocido') + '.';
    }
  }

  function hideFallback() {
    const notice = E['notice-fallback'];
    if (notice) notice.hidden = true;
  }

  let analyzeTimer = 0;
  let analyzeController = null;
  let analyzeToken = 0;

  // Se llama en cada evento input. Primero pinta el an local (cero red),
  // luego programa la consulta al servidor. El token corta las respuestas
  // fuera de orden y el AbortController cancela la petición en vuelo.
  function onPasswordInput() {
    const input = E['pw-input'];
    if (!input) return;
    const password = input.value;
    lastAnalyzed = password;

    if (analyzeTimer) {
      clearTimeout(analyzeTimer);
      analyzeTimer = 0;
    }
    if (analyzeController) {
      analyzeController.abort();
      analyzeController = null;
    }
    const token = ++analyzeToken;

    scheduleHibp();

    if (!password) {
      currentResult = null;
      renderAll(null);
      setPending(false);
      hideFallback();
      return;
    }

    currentResult = analyzeLocally(password);
    renderAll(currentResult);
    setPending(true);
    analyzeTimer = setTimeout(() => {
      analyzeTimer = 0;
      runAnalyze(password, token);
    }, DEBOUNCE_ANALYZE);
  }

  async function runAnalyze(password, token) {
    const controller = new AbortController();
    analyzeController = controller;
    try {
      const raw = await api.analyze({ password: password, context: [] }, { signal: controller.signal });
      if (token !== analyzeToken) return; // respuesta obsoleta: se descarta
      const result = normalizeAnalyze(raw || {}, password);
      currentResult = result;
      renderAll(result);
      hideFallback();
    } catch (err) {
      if (token !== analyzeToken) return;
      if (isAbort(err)) return;
      // Aqu no se borra nada de lo pintado: el an local sigue en pie.
      showFallback(err);
    } finally {
      if (analyzeController === controller) analyzeController = null;
      if (token === analyzeToken) setPending(false);
    }
  }

  function retryAnalyze() {
    const input = E['pw-input'];
    if (!input || !input.value) return;
    if (analyzeController) {
      analyzeController.abort();
      analyzeController = null;
    }
    const token = ++analyzeToken;
    hideFallback();
    setPending(true);
    runAnalyze(input.value, token);
  }

  /* ---------------------------------------------------------- HIBP */

  const hibpWorker = (function makeWorker() {
    try {
      if (typeof Worker === 'undefined') return null;
      return new Worker('sha1.worker.js');
    } catch (err) {
      // file:// bloquea los Web Workers en algunos navegadores: no es un fallo
      // de la página, solo se pierde esta comprobación.
      return null;
    }
  }());

  let hibpTimer = 0;
  let hibpController = null;
  let hibpToken = 0;
  let hibpRequestId = 0;

  function hashInWorker(password) {
    return new Promise((resolve) => {
      if (!hibpWorker) {
        resolve(null);
        return;
      }
      const id = ++hibpRequestId;
      const timer = setTimeout(() => {
        cleanup();
        resolve(null);
      }, 4000);

      function onMessage(event) {
        const data = event.data || {};
        if (data.id !== id) return;
        cleanup();
        resolve(data.ok === true ? str(data.hash) || null : null);
      }
      function onError() {
        cleanup();
        resolve(null);
      }
      function cleanup() {
        clearTimeout(timer);
        hibpWorker.removeEventListener('message', onMessage);
        hibpWorker.removeEventListener('error', onError);
      }

      hibpWorker.addEventListener('message', onMessage);
      hibpWorker.addEventListener('error', onError);
      hibpWorker.postMessage({ id: id, text: password });
    });
  }

  function setHibp(key, label, extra, note) {
    const chip = E['hibp-state'];
    if (chip) {
      chip.dataset.state = key;
      chip.textContent = label;
    }
    const panel = E['hibp-panel'];
    if (panel) panel.dataset.state = key;
    setText('hibp-count', extra || '');
    // Solo se reprograma el resumen cuando la nota cambia: si no, cada
    // actualizacion de HIBP retrasaria el anuncio del veredicto un segundo.
    const nextNote = note || '';
    if (nextNote !== HIBP_NOTE.text) {
      HIBP_NOTE.text = nextNote;
      scheduleVerdict(currentResult);
    }
  }

  // Mientras la comprobación está en vuelo el campo se mantiene enmascarado y
  // el botón de revelar se bloquea: así no aparece la contraseña en claro en
  // ningún momento de la consulta.
  function setFieldMasked(masked) {
    const input = E['pw-input'];
    const button = E['btn-toggle-pw'];
    const wrap = E['pw-input-wrap'];
    if (!input) return;
    if (masked) {
      if (input.type === 'text') input.type = 'password';
      if (button) {
        button.setAttribute('aria-pressed', 'false');
        button.setAttribute('aria-label', 'Mostrar contraseña');
        button.disabled = true;
      }
      if (wrap) wrap.dataset.masked = 'true';
    } else {
      if (button) {
        button.disabled = false;
        button.setAttribute('aria-label', input.type === 'text' ? 'Ocultar contraseña' : 'Mostrar contraseña');
      }
      if (wrap) delete wrap.dataset.masked;
    }
  }

  function scheduleHibp() {
    if (hibpTimer) clearTimeout(hibpTimer);
    hibpTimer = setTimeout(() => {
      hibpTimer = 0;
      const input = E['pw-input'];
      runHibp(input ? input.value : '', ++hibpToken);
    }, DEBOUNCE_HIBP);
  }

  async function runHibp(password, token) {
    if (!password) {
      setFieldMasked(false);
      setHibp('idle', 'inactivo', '', '');
      return;
    }
    if (!HIBP_ENABLED) {
      setHibp('unavailable', 'desactivado', 'hibpEnabled = false en config.js', '');
      return;
    }
    if (!BASE) {
      setHibp('unavailable', 'sin servidor', 'Configura apiBase en config.js para consultar /api/hibp.', '');
      return;
    }
    if (!hibpWorker) {
      setHibp('unavailable', 'no disponible', 'Web Workers no disponibles en este contexto.', '');
      return;
    }

    setFieldMasked(true);
    setHibp('pending', 'calculando', 'SHA-1 en el navegador...', '');

    const hash = await hashInWorker(password);
    if (token !== hibpToken) return;
    if (!hash) {
      setFieldMasked(false);
      setHibp('unavailable', 'fallo local', 'No se pudo calcular el SHA-1 en este navegador.', '');
      return;
    }

    // De los 40 hex del SHA-1 salen al servidor cinco. El resto se queda aqu.
    const prefix = hash.slice(0, 5).toUpperCase();
    const suffix = hash.slice(5).toUpperCase();
    if (hibpController) hibpController.abort();
    hibpController = new AbortController();

    try {
      const raw = await api.hibp(prefix, { signal: hibpController.signal });
      if (token !== hibpToken) return;
      // El cruce se hace aqu, en el cliente: el servidor no sabe cual es
      // nuestra contraseña.
      const hit = arr(raw && raw.suffixes).filter((s) => str(s).split(':')[0].toUpperCase() === suffix)[0];
      if (hit) {
        const count = num(String(hit).split(':')[1], num(raw && raw.count, 0));
        setHibp('breached', 'en brechas', count.toLocaleString('es-CO') + ' apariciones en el rango ' + prefix,
          'Verificación de brechas: aparece ' + count.toLocaleString('es-CO') + ' veces en el rango ' + prefix + '.');
      } else {
        setHibp('clean', 'sin coincidencias', 'Ningún hash del rango ' + prefix + ' coincide con el tuyo.',
          'Verificación de brechas: sin coincidencias en el rango consultado.');
      }
    } catch (err) {
      if (isAbort(err)) return;
      // Neutral a proposito: HIBP es información extra, nunca un bloqueante.
      setHibp('unavailable', 'no disponible', 'La consulta no pudo completarse; el resto del panel sigue igual.', '');
    } finally {
      if (token === hibpToken) setFieldMasked(false);
    }
  }
  /* ------------------------------------------------------- generador */

  // Los tres alfabetos que acepta el contrato. 'web' usa el subconjunto de
  // s que sobrevive a una URL sin codificar.
  const ALPHABETS = {
    alnum: { lower: true, upper: true, digits: true, symbols: false },
    web: { lower: true, upper: true, digits: true, symbols: true },
    full: { lower: true, upper: true, digits: true, symbols: true }
  };
  const SYMBOLS = "!#$%&()*+,-./:;<=>?@[]^_{|}~";
  const AMBIGUOUS = '0O1lI';
  let lastGenerated = '';

  function readGroups() {
    return {
      lower: Boolean(E['gen-use-lower'] && E['gen-use-lower'].checked),
      upper: Boolean(E['gen-use-upper'] && E['gen-use-upper'].checked),
      digits: Boolean(E['gen-use-digits'] && E['gen-use-digits'].checked),
      symbols: Boolean(E['gen-use-symbols'] && E['gen-use-symbols'].checked)
    };
  }

  function groupsMatch(groups, canonical) {
    return groups.lower === canonical.lower && groups.upper === canonical.upper &&
      groups.digits === canonical.digits && groups.symbols === canonical.symbols;
  }

  function applyAlphabetToGroups() {
    const select = E['gen-alphabet'];
    const canonical = ALPHABETS[str(select && select.value, 'web')] || ALPHABETS.web;
    if (E['gen-use-lower']) E['gen-use-lower'].checked = canonical.lower;
    if (E['gen-use-upper']) E['gen-use-upper'].checked = canonical.upper;
    if (E['gen-use-digits']) E['gen-use-digits'].checked = canonical.digits;
    if (E['gen-use-symbols']) E['gen-use-symbols'].checked = canonical.symbols;
  }

  function buildCharset(groups, avoidAmbiguous) {
    let out = '';
    const add = (chunk) => {
      for (const ch of chunk) {
        if (avoidAmbiguous && AMBIGUOUS.indexOf(ch) >= 0) continue;
        out += ch;
      }
    };
    if (groups.lower) add('abcdefghijklmnopqrstuvwxyz');
    if (groups.upper) add('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
    if (groups.digits) add('0123456789');
    if (groups.symbols) add(SYMBOLS);
    return Array.from(new Set(out));
  }

  // Rechazo del residuo: tomar valor % n introduce sesgo hacia los indices
  // bajos, que en un alfabeto de 68 caracteres sesgaría la distribución.
  function randomIndex(size) {
    if (size <= 0) return 0;
    const limit = Math.floor(0x100000000 / size) * size;
    if (!window.crypto || typeof window.crypto.getRandomValues !== 'function') {
      return Math.floor(Math.random() * size);
    }
    const buffer = new Uint32Array(1);
    let value = 0;
    do {
      window.crypto.getRandomValues(buffer);
      value = buffer[0];
    } while (value >= limit);
    return value % size;
  }

  function presentGroups(password) {
    const groups = readGroups();
    return {
      lower: groups.lower && /[a-z]/.test(password),
      upper: groups.upper && /[A-Z]/.test(password),
      digits: groups.digits && /[0-9]/.test(password),
      symbols: groups.symbols && /[^a-zA-Z0-9]/.test(password)
    };
  }

  function countPresent(password) {
    const present = presentGroups(password);
    return Object.keys(present).filter((k) => present[k]).length;
  }

  function generateLocal(length, groups, avoidAmbiguous, minClasses) {
    const charset = buildCharset(groups, avoidAmbiguous);
    if (!charset.length) return null;

    const pools = [];
    if (groups.lower) pools.push(charset.filter((c) => /[a-z]/.test(c)));
    if (groups.upper) pools.push(charset.filter((c) => /[A-Z]/.test(c)));
    if (groups.digits) pools.push(charset.filter((c) => /[0-9]/.test(c)));
    if (groups.symbols) pools.push(charset.filter((c) => /[^a-zA-Z0-9]/.test(c)));
    const usable = pools.filter((pool) => pool.length);
    if (!usable.length) return null;
    const target = clamp(minClasses, 1, usable.length);

    let last = '';
    for (let attempt = 0; attempt < 40; attempt += 1) {
      let candidate = '';
      for (let i = 0; i < length; i += 1) candidate += charset[randomIndex(charset.length)];
      last = candidate;
      if (countPresent(candidate) >= target) return candidate;
    }

    // Reintentos agotados: se fuerza un carácter por clase en vez de
    // devolver algo que incumple el requisito pedido.
    const built = new Array(length);
    for (let i = 0; i < length; i += 1) built[i] = charset[randomIndex(charset.length)];
    usable.slice(0, target).forEach((pool, i) => {
      built[i] = pool[randomIndex(pool.length)];
    });
    return built.join('');
  }

  function setGenStatus(text, state) {
    const node = E['gen-status'];
    if (!node) return;
    node.textContent = text;
    node.dataset.state = state || 'idle';
  }

  function renderGenerated(result, note) {
    lastGenerated = str(result.password);
    if (E['gen-output']) E['gen-output'].value = lastGenerated;
    setText('gen-entropy', num(result.entropy_bits, 0) + ' bits');
    setText('gen-alphabet-size', num(result.alphabet_size) + ' símbolos');
    setText('gen-classes', num(result.classes_present) + ' de ' + Object.keys(readGroups()).filter((k) => readGroups()[k]).length);
    setText('gen-policy', result.policy_satisfied === true ? 'si' : 'no');
    const analysis = result.analysis && typeof result.analysis === 'object' ? result.analysis : null;
    setText('gen-analysis', analysis ? str(analysis.explanation, '') : 'Sin análisis asociado.');
    setGenStatus(note || 'Generada. No sobrescribe el campo del analizador.', 'ok');
  }

  async function doGenerate() {
    const button = E['gen-submit'];
    if (button) button.disabled = true;
    try {
      const slider = E['gen-length'];
      const length = clamp(num(slider && slider.value, 20), POLICY.min_length, POLICY.max_length);
      const alphabet = str(E['gen-alphabet'] && E['gen-alphabet'].value, 'web');
      const avoidAmbiguous = Boolean(E['gen-avoid-ambiguous'] && E['gen-avoid-ambiguous'].checked);
      const minClasses = clamp(num(E['gen-min-classes'] && E['gen-min-classes'].value, 3), 1, 4);
      const groups = readGroups();
      const canonical = ALPHABETS[alphabet] || ALPHABETS.web;

      if (!Object.keys(groups).some((k) => groups[k])) {
        setGenStatus('Selecciona al menos un grupo de caracteres.', 'error');
        return;
      }

      // Si los grupos coinciden con un alfabeto del contrato, la petición va al
      // servidor. Si el usuario los personalizo, se genera en el navegador para
      // respetar exactamente lo que pidio.
      if (BASE && groupsMatch(groups, canonical)) {
        const raw = await api.generate({
          length: length,
          alphabet: alphabet,
          avoid_ambiguous: avoidAmbiguous,
          min_classes: minClasses
        });
        if (raw && typeof raw === 'object' && str(raw.password)) {
          renderGenerated(raw, 'Generada por el servidor.');
          return;
        }
      }

      const local = generateLocal(length, groups, avoidAmbiguous, minClasses);
      if (!local) {
        setGenStatus('El alfabeto elegido quedó vacío.', 'error');
        return;
      }
      const analysis = analyzeLocally(local);
      renderGenerated({
        password: local,
        length: local.length,
        alphabet: alphabet,
        alphabet_size: buildCharset(groups, avoidAmbiguous).length,
        entropy_bits: round(local.length * Math.log2(Math.max(2, buildCharset(groups, avoidAmbiguous).length)), 1),
        classes_present: countPresent(local),
        policy_satisfied: analysis.valid === true,
        analysis: analysis
      }, 'Generada en el navegador (personalizacion o servidor no disponible).');
    } catch (err) {
      if (isAbort(err)) return;
      const slider = E['gen-length'];
      const length = clamp(num(slider && slider.value, 20), POLICY.min_length, POLICY.max_length);
      const groups = readGroups();
      const avoidAmbiguous = Boolean(E['gen-avoid-ambiguous'] && E['gen-avoid-ambiguous'].checked);
      const minClasses = clamp(num(E['gen-min-classes'] && E['gen-min-classes'].value, 3), 1, 4);
      const local = generateLocal(length, groups, avoidAmbiguous, minClasses);
      if (local) {
        const analysis = analyzeLocally(local);
        renderGenerated({
          password: local,
          length: local.length,
          alphabet: str(E['gen-alphabet'] && E['gen-alphabet'].value, 'web'),
          alphabet_size: buildCharset(groups, avoidAmbiguous).length,
          entropy_bits: round(local.length * Math.log2(Math.max(2, buildCharset(groups, avoidAmbiguous).length)), 1),
          classes_present: countPresent(local),
          policy_satisfied: analysis.valid === true,
          analysis: analysis
        }, 'Generada en el navegador: el servidor no respondió.');
      } else {
        setGenStatus('No se pudo generar: revisa los grupos de caracteres.', 'error');
      }
    } finally {
      if (button) button.disabled = false;
    }
  }

  async function copyToClipboard(text) {
    if (window.isSecureContext && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch (err) {
        // sin permiso o sin foco: se intenta el metodo antiguo
      }
    }
    const area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.top = '0';
    area.style.left = '0';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    let ok = false;
    try {
      ok = document.execCommand('copy');
    } catch (err) {
      ok = false;
    }
    document.body.removeChild(area);
    return ok;
  }

  async function onCopyGenerated() {
    if (!lastGenerated) {
      setGenStatus('Genera una contraseña antes de copiar.', 'error');
      return;
    }
    const ok = await copyToClipboard(lastGenerated);
    setGenStatus(ok ? 'Copia al portapapeles confirmada.' : 'No se pudo copiar: selecciona el texto a mano.',
      ok ? 'ok' : 'error');
  }

  /* -------------------------------------------------------- auditoria */

  // Clave efímera de sesión: el HMAC sirve para que el servidor pueda correlacion
  // dos análisis del mismo cliente sin recibir jamás la contraseña. Se descarta
  // al cerrar la pestana, asi que dos recibos del mismo usuario no son
  // comparables entre sesiones.
  const SESSION_KEY = (function makeSessionKey() {
    const bytes = new Uint8Array(32);
    if (window.crypto && typeof window.crypto.getRandomValues === 'function') {
      window.crypto.getRandomValues(bytes);
    } else {
      for (let i = 0; i < bytes.length; i += 1) bytes[i] = Math.floor(Math.random() * 256);
    }
    return bytes;
  }());

  function toHex(buffer) {
    return Array.from(new Uint8Array(buffer)).map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  async function hmacOf(password) {
    if (!window.crypto || !window.crypto.subtle) return null;
    try {
      const key = await window.crypto.subtle.importKey('raw', SESSION_KEY, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      const signature = await window.crypto.subtle.sign('HMAC', key, new TextEncoder().encode(password));
      return toHex(signature);
    } catch (err) {
      return null;
    }
  }

  function setAuditStatus(text, state) {
    const node = E['audit-status'];
    if (!node) return;
    node.textContent = text;
    node.dataset.state = state || 'idle';
  }

  async function onAudit() {
    const input = E['pw-input'];
    if (!input || !input.value) {
      setAuditStatus('Analiza una contraseña primero.', 'error');
      return;
    }
    if (!currentResult) return;
    setAuditStatus('emitiendo...', 'idle');
    try {
      const hmac = await hmacOf(input.value);
      const payload = {
        policy_id: POLICY.policy_id,
        score: num(currentResult.score),
        guesses_log10: num(currentResult.guesses_log10),
        findings: arr(currentResult.findings).map((f) => str(f && f.id)).filter(Boolean),
        pw_hmac: hmac
      };
      const raw = await api.audit(payload);
      const receipt = str(raw && raw.receipt, '');
      setText('audit-receipt', receipt
        ? 'id ' + str(raw.audit_id) + ' \u00b7 ' + str(raw.ts) + '\n' + receipt
        : 'El servidor respondió sin recibo.');
      setAuditStatus(receipt ? 'recibo emitido' : 'respuesta sin recibo', receipt ? 'ok' : 'error');
    } catch (err) {
      if (isAbort(err)) return;
      setAuditStatus('No se pudo emitir: ' + str(err && err.message, 'error'), 'error');
    }
  }
  /* --------------------------------------------------------- cableado */

  function onTogglePassword() {
    const input = E['pw-input'];
    const button = E['btn-toggle-pw'];
    if (!input || !button) return;
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    button.setAttribute('aria-pressed', show ? 'true' : 'false');
    button.setAttribute('aria-label', show ? 'Ocultar contraseña' : 'Mostrar contraseña');
    button.title = show ? 'Ocultar contraseña' : 'Mostrar contraseña';
  }

  function onClearPassword() {
    const input = E['pw-input'];
    if (!input) return;
    input.value = '';
    input.focus();
    onPasswordInput();
  }

  function onUseGenerated() {
    const input = E['pw-input'];
    if (!input) return;
    if (!lastGenerated) {
      setGenStatus('Genera una contraseña primero.', 'error');
      return;
    }
    input.value = lastGenerated;
    input.focus();
    onPasswordInput();
    const panel = E['panel-analizador'];
    if (panel && panel.scrollIntoView) panel.scrollIntoView({ block: 'start' });
  }

  function wireEvents() {
    const input = E['pw-input'];
    if (input) input.addEventListener('input', onPasswordInput);

    if (E['btn-toggle-pw']) E['btn-toggle-pw'].addEventListener('click', onTogglePassword);
    if (E['btn-clear-pw']) E['btn-clear-pw'].addEventListener('click', onClearPassword);
    if (E['btn-retry']) E['btn-retry'].addEventListener('click', retryAnalyze);
    if (E['btn-audit']) E['btn-audit'].addEventListener('click', onAudit);
    if (E['btn-recheck']) E['btn-recheck'].addEventListener('click', () => { refreshConnection(); });

    const form = E['gen-form'];
    if (form) form.addEventListener('submit', (event) => { event.preventDefault(); doGenerate(); });
    if (E['btn-gen-copy']) E['btn-gen-copy'].addEventListener('click', onCopyGenerated);
    if (E['btn-gen-analyze']) E['btn-gen-analyze'].addEventListener('click', onUseGenerated);

    const slider = E['gen-length'];
    if (slider) {
      slider.addEventListener('input', () => {
        const value = E['gen-length-value'];
        if (value) value.textContent = String(clamp(num(slider.value, POLICY.min_length), POLICY.min_length, POLICY.max_length));
      });
    }
    if (E['gen-alphabet']) E['gen-alphabet'].addEventListener('change', applyAlphabetToGroups);
  }

  /* ---------------------------------------------------------- arranque */

  async function refreshConnection() {
    if (!BASE) {
      setConnState('local', 'modo local \u00b7 sin backend');
      applyPolicy(FALLBACK_POLICY);
      return;
    }
    setConnState('checking', 'comprobando...');
    try {
      const health = await api.health();
      setConnState('online', 'en linea \u00b7 ' + str(health.service, 'api') + ' v' + str(health.version, '?'));
    } catch (err) {
      if (API_BASE) {
        setConnState('offline', 'sin conexión con el servidor');
      } else {
        // Sin apiBase, BASE es el origen de esta misma página, y en GitHub
        // Pages ese origen NO sirve la API: el 404 es esperable, no un fallo.
        // Decir "sin conexión" sería culpar a un servicio que no está en
        // marcha. El análisis sigue funcionando en local, así que lo honesto
        // es modo local más la causa exacta: falta rellenar apiBase.
        setConnState('local', 'modo local · sin backend');
        setText('fallback-detail', 'Falta apiBase en config.js: no hay backend contra el que consultar, ' +
          'así que todo el análisis se resuelve en el navegador. Rellena apiBase con la URL de la API.');
      }
      return;
    }
    try {
      const normalized = normalizePolicy(await api.policy());
      // Si la política no valida, se conserva la del espejo local en vez de
      // dejar la lista de requisitos vacia.
      if (normalized) applyPolicy(normalized);
    } catch (err) {
      // Sin política del servidor se sigue con la local: la app no se rompe.
    }
  }

  function boot() {
    applyPolicy(FALLBACK_POLICY);
    wireEvents();
    renderAll(null);
    setHibp('idle', 'inactivo', '', '');
    if (!BASE) {
      setConnState('local', 'modo local \u00b7 sin backend');
      setText('fallback-detail', 'No hay apiBase configurado en config.js, así que todo el análisis se resuelve ' +
        'en el navegador. Rellena apiBase para conectar con el backend de Python.');
    } else {
      refreshConnection();
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
}());
