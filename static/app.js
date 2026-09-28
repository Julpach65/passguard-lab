/* PassGuard · probador y generador de contraseñas.
 *
 * El veredicto lo calcula el servidor: `analyzer.py` es la autoridad y esta
 * interfaz solo lo pinta. Hay un análisis local para cuando la API no responde,
 * pero va marcado como estimación: sin servidor no se puede consultar el
 * diccionario de contraseñas comunes, y fingir que sí se puede sería mentir.
 */
(function () {
    'use strict';

    const CFG = window.PASSGUARD_CONFIG || {};
    const API_BASE = String(CFG.apiBase || '').replace(/\/+$/, '');
    const CLIENT_HEADER = 'X-Passguard-Client';
    const CLIENT_VALUE = '1';
    const TIMEOUT_MS = 8000;
    const DEBOUNCE_MS = 250;

    const E = {};
    [
        'status-badge', 'pw-input', 'btn-toggle-pw', 'btn-clear-pw', 'verdict-live',
        'strength-score', 'requirements-list', 'notice-fallback', 'fallback-detail',
        'btn-retry', 'gen-form', 'gen-length', 'gen-length-value', 'gen-submit',
        'gen-output', 'btn-gen-copy', 'btn-gen-analyze', 'gen-status',
    ].forEach(function (id) { E[id] = document.getElementById(id); });

    function str(value, fallback) {
        return typeof value === 'string' ? value : (fallback || '');
    }
    function num(value) {
        return typeof value === 'number' && isFinite(value) ? value : 0;
    }
    function round(value, places) {
        const factor = Math.pow(10, places || 0);
        return Math.round(num(value) * factor) / factor;
    }
    function setText(node, text) {
        if (node) node.textContent = text;
    }

    function ApiError(code, message) {
        const err = new Error(message || code);
        err.code = code || 'error';
        return err;
    }

    function isAbort(err) {
        return Boolean(err) && (err.name === 'AbortError' || err.code === 'aborted');
    }

    /* ------------------------------------------------------------- transporte */

    function request(path, options) {
        const opt = options || {};
        const method = opt.method || 'GET';
        const controller = new AbortController();
        const external = opt.signal || null;
        const relay = function () { controller.abort(); };
        let timer = null;

        if (external) {
            if (external.aborted) return Promise.reject(ApiError('aborted', 'cancelado'));
            external.addEventListener('abort', relay, { once: true });
        }
        if (!API_BASE) {
            return Promise.reject(ApiError('api_unavailable', 'Sin backend configurado.'));
        }

        timer = setTimeout(function () { controller.abort(); }, TIMEOUT_MS);

        const headers = { Accept: 'application/json' };
        if (method !== 'GET') {
            headers['Content-Type'] = 'application/json';
            // Esta cabecera es la que dispara el preflight: un formulario o un
            // <img> desde otra página no pueden ponerla, así que el servidor
            // recibe una petición que solo puede venir de este cliente.
            headers[CLIENT_HEADER] = CLIENT_VALUE;
        }

        return fetch(API_BASE + path, {
            method: method,
            headers: headers,
            body: method === 'GET' ? undefined : JSON.stringify(opt.body || {}),
            signal: controller.signal
        }).then(function (response) {
            return response.text().then(function (raw) {
                let parsed = null;
                try { parsed = raw ? JSON.parse(raw) : null; } catch (err) { parsed = null; }
                if (!response.ok) {
                    // El servidor responde siempre con {"error": {code, message}}.
                    const detail = parsed && parsed.error ? parsed.error : null;
                    throw ApiError(
                        detail ? detail.code : 'http_' + response.status,
                        detail ? detail.message : ('El servidor respondió ' + response.status + '.')
                    );
                }
                return parsed;
            });
        }).catch(function (err) {
            if (isAbort(err)) throw ApiError('aborted', 'La petición se canceló o tardó demasiado.');
            if (err && err.code) throw err;
            throw ApiError('network', 'No hay conexión con ' + API_BASE + '.');
        }).finally(function () {
            clearTimeout(timer);
            if (external) external.removeEventListener('abort', relay);
        });
    }

    /* ---------------------------------------------------------------- política */

    // Espejo de policy.py. Solo entra en juego si GET /api/policy no responde,
    // para que la página siga siendo utilizable sin servidor. En cuanto el
    // servidor contesta, este objeto se descarta: las reglas no están
    // duplicadas en el HTML que dibuja la lista.
    const FALLBACK_POLICY = {
        policy_id: 'upsin-seg-2026-c1',
        version: '1.0.0',
        min_length: 12,
        max_length: 128,
        min_entropy_bits: 40,
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
        ]
    };

    // Espejo de policy.CRITICAL_RULE_IDS: qué reglas invalidan el veredicto.
    // Si cambia en el servidor, hay que cambiarlo aquí.
    const CRITICAL = ['length', 'not_common', 'no_sequence', 'no_keyboard', 'no_repeat', 'entropy'];

    const POLICY = { fromServer: false, data: FALLBACK_POLICY };

    function normalizePolicy(raw) {
        const body = raw && typeof raw === 'object' ? raw : null;
        if (!body || !Array.isArray(body.rules) || !Array.isArray(body.scores)) return null;
        POLICY.fromServer = true;
        POLICY.data = body;
        return body;
    }

    /* ------------------------------------------------- análisis local (respaldo) */

    // Un puñado de las contraseñas más usadas del mundo. El corpus real tiene
    // 3.755 entradas y vive en el servidor; esto no pretende sustituirlo, solo
    // no dejar la página inútil cuando la API no responde.
    const COMMON = ['123456', '123456789', 'qwerty', 'abc123', 'password', '111111',
        '1234567', 'iloveyou', 'sunshine', 'princess', 'admin', 'welcome', '000000',
        'contrasena', 'contraseña', '123123', 'qwerty123', 'letmein', 'monkey',
        'dragon', 'passw0rd', 'baseball', 'football', 'master', 'shadow', 'michael'];

    function del33tFold(text) {
        return text
            .replace(/[4@]/g, 'a').replace(/[8]/g, 'b').replace(/[(<{]/g, 'c')
            .replace(/[3]/g, 'e').replace(/[6]/g, 'g').replace(/[17]/g, 'i')
            .replace(/[!|1]/g, 'l').replace(/[0]/g, 'o').replace(/[9]/g, 'q')
            .replace(/[$5]/g, 's').replace(/[2]/g, 'z').replace(/[+]/g, 't');
    }

    function hasSequence(text) {
        const flat = text.replace(/[^a-z0-9]/g, '');
        for (let i = 0; i + 3 < flat.length; i += 1) {
            const chunk = flat.slice(i, i + 4);
            let asc = true;
            let desc = true;
            for (let k = 1; k < chunk.length; k += 1) {
                const delta = chunk.charCodeAt(k) - chunk.charCodeAt(k - 1);
                if (delta !== 1) asc = false;
                if (delta !== -1) desc = false;
            }
            if (asc || desc) return true;
        }
        return false;
    }

    const KEYBOARD = ['qwerty', 'asdfgh', 'zxcvbn', 'qazwsx', '1qaz2wsx', 'wsxedc',
        'qwer', 'asdf', 'zxcv', 'poiuy', 'mnbvc', 'lkjh', '0987', '1234', '4321', '5678'];

    function hasKeyboard(text) {
        const flat = text.toLowerCase().replace(/[^a-z0-9]/g, '');
        return KEYBOARD.some(function (walk) { return flat.includes(walk); });
    }

    function hasRepeat(text) {
        if (/(.)\1{1,}/.test(text)) return true;              // carácter repetido
        if (/(.{2,})\1+/.test(text)) return true;             // bloque repetido
        return false;
    }

    function hasDate(text) {
        if (/(19|20)\d{2}/.test(text)) return true;
        return /\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}/.test(text);
    }

    function charsetSize(checks) {
        let size = 0;
        if (checks.lowercase) size += 26;
        if (checks.uppercase) size += 26;
        if (checks.number) size += 10;
        if (checks.symbol) size += 32;
        return Math.max(size, 2);
    }

    // Devuelve la misma forma que /api/analyze para que el pintado no sepa de
    // dónde salió el veredicto.
    function analyzeLocally(password) {
        const lower = password.toLowerCase();
        const classes = {
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            number: /[0-9]/.test(password),
            symbol: /[^A-Za-z0-9]/.test(password)
        };
        const bits = round(password.length * Math.log2(charsetSize(classes)), 2);
        const checks = {
            length: password.length >= num(POLICY.data.min_length),
            uppercase: classes.uppercase,
            lowercase: classes.lowercase,
            number: classes.number,
            symbol: classes.symbol,
            not_common: COMMON.indexOf(lower) === -1 && COMMON.indexOf(del33tFold(lower)) === -1,
            no_sequence: !hasSequence(lower),
            no_keyboard: !hasKeyboard(password),
            no_repeat: !hasRepeat(password),
            no_date: !hasDate(password),
            entropy: bits >= num(POLICY.data.min_entropy_bits)
        };
        const failed = CRITICAL.filter(function (id) { return !checks[id]; });
        const findings = [];
        if (!checks.not_common) findings.push({ id: 'dictionary', label: 'Es una contraseña común', severity: 'critical' });
        if (!checks.no_repeat) findings.push({ id: 'repeat', label: 'Repite un bloque de caracteres', severity: 'high' });
        if (!checks.no_keyboard) findings.push({ id: 'keyboard', label: 'Recorre el teclado de forma contigua', severity: 'high' });
        if (!checks.no_sequence) findings.push({ id: 'sequence', label: 'Contiene una secuencia', severity: 'medium' });
        if (!checks.no_date) findings.push({ id: 'date', label: 'Contiene un año o una fecha', severity: 'medium' });
        if (!checks.entropy) findings.push({ id: 'entropy', label: 'La entropía estimada es baja', severity: 'critical' });

        return {
            policy_id: POLICY.data.policy_id,
            valid: failed.length === 0,
            checks: checks,
            missing: failed.map(function (id) {
                const rule = (POLICY.data.rules || []).find(function (r) { return r.id === id; });
                return rule ? rule.label : id;
            }),
            rules: (POLICY.data.rules || []).map(function (rule) {
                return { id: rule.id, label: rule.label, kind: rule.kind, value: rule.value, ok: Boolean(checks[rule.id]) };
            }),
            // No se devuelve nivel de score a propósito. Aquí los bits salen
            // de longitud × log2(alfabeto), y el servidor hace justo lo
            // contrario: se queda con el mínimo entre fuerza bruta y el mejor
            // ataque dirigido, que es lo que hunde una contraseña repetida. Sin
            // ese cálculo, un nivel aquí sería un aprobado falso: la misma
            // contraseña que el servidor dice "muy débil" saldría "muy fuerte"
            // y con la lista en rojo. Poner los bits y callar la nota es más
            // feo, pero es cierto.
            score: null,
            score_label: 'estimación local',
            score_color: '',
            entropy_bits: bits,
            findings: findings,
            source: 'local'
        };
    }

    /* ------------------------------------------------------------- renderizado */

    function ruleItem(label, ok) {
        const item = document.createElement('li');
        item.dataset.ok = ok === null ? 'pending' : (ok ? 'true' : 'false');
        item.textContent = label;
        return item;
    }

    function renderRules(result) {
        const list = E['requirements-list'];
        if (!list) return;
        list.textContent = '';
        (result.rules || []).forEach(function (rule) {
            list.appendChild(ruleItem(str(rule.label, str(rule.id)), rule.ok));
        });
    }

    // Antes de escribir nada, los requisitos ya se listan a la espera. Con la
    // lista vacía la página parece rota hasta que pulsas una tecla, y además
    // se pierde la única explicación de qué se está comprobando.
    function renderPending() {
        const list = E['requirements-list'];
        if (!list) return;
        list.textContent = '';
        (POLICY.data.rules || []).forEach(function (rule) {
            list.appendChild(ruleItem(str(rule.label, str(rule.id)), null));
        });
    }

    // Una línea de motivo, no un párrafo: el detalle vive en la API.
    function reasonOf(result) {
        if (result.valid) return 'Cumple la política de la asignatura.';
        const findings = Array.isArray(result.findings) ? result.findings : [];
        if (findings.length && str(findings[0].label)) return findings[0].label + '.';
        const missing = Array.isArray(result.missing) ? result.missing : [];
        if (missing.length) return 'Incumple: ' + str(missing[0]).toLowerCase() + '.';
        return 'No cumple la política.';
    }

    function renderVerdict(result) {
        const rules = (result.rules || []).filter(function (rule) { return rule.ok; }).length;
        const total = (result.rules || []).length;
        setText(E['strength-score'],
            str(result.score_label) + ' · ' + round(num(result.entropy_bits), 1) + ' bits · ' + rules + '/' + total + ' requisitos');

        const node = E['verdict-live'];
        if (node) {
            node.textContent = reasonOf(result);
            node.dataset.state = result.valid ? 'ok' : 'error';
        }
    }

    function reset() {
        renderPending();
        setText(E['strength-score'], '—');
        const node = E['verdict-live'];
        if (node) {
            node.textContent = 'La contraseña aún no se ha evaluado.';
            node.dataset.state = '';
        }
    }

    function showFallback(message) {
        if (E['notice-fallback']) E['notice-fallback'].hidden = false;
        setText(E['fallback-detail'], message || 'Sin servidor: se muestra una estimación local.');
    }

    function hideFallback() {
        if (E['notice-fallback']) E['notice-fallback'].hidden = true;
    }

    function setConn(state, text) {
        if (!E['status-badge']) return;
        E['status-badge'].dataset.state = state;
        E['status-badge'].textContent = text;
    }

    /* ------------------------------------------------------------- probador */

    let analyzeToken = 0;
    let analyzeController = null;
    let debounceTimer = null;

    function render(result) {
        renderRules(result);
        renderVerdict(result);
    }

    function runAnalyze(password) {
        if (analyzeController) analyzeController.abort();
        const token = ++analyzeToken;
        const controller = new AbortController();
        analyzeController = controller;

        request('/api/analyze', {
            method: 'POST',
            body: { password: password, context: [] },
            signal: controller.signal
        }).then(function (body) {
            if (token !== analyzeToken) return;   // respuesta obsoleta
            hideFallback();
            render(normalizeAnalyze(body));
        }).catch(function (err) {
            if (token !== analyzeToken || isAbort(err)) return;
            // El análisis local queda en pie, pero marcado: sin servidor no se
            // ha consultado el diccionario real y el veredicto es provisional.
            render(analyzeLocally(password));
            showFallback(str(err && err.message, 'Sin servidor: se muestra una estimación local.'));
            setConn('local', 'modo local · sin backend');
        }).finally(function () {
            if (analyzeController === controller) analyzeController = null;
        });
    }

    function normalizeAnalyze(body) {
        const data = body && typeof body === 'object' ? body : {};
        if (!Array.isArray(data.rules)) {
            // Un servidor viejo que no mande `rules` se reconstruye desde la
            // política, para que la lista siga siendo la de policy.py.
            const checks = data.checks || {};
            data.rules = (POLICY.data.rules || []).map(function (rule) {
                return { id: rule.id, label: rule.label, kind: rule.kind, value: rule.value, ok: Boolean(checks[rule.id]) };
            });
        }
        data.source = 'server';
        return data;
    }

    function onPasswordInput() {
        const value = E['pw-input'] ? E['pw-input'].value : '';
        if (debounceTimer) clearTimeout(debounceTimer);
        if (!value) {
            ++analyzeToken;
            hideFallback();
            reset();
            return;
        }
        debounceTimer = setTimeout(function () { runAnalyze(value); }, DEBOUNCE_MS);
    }

    function onTogglePassword() {
        const input = E['pw-input'];
        const button = E['btn-toggle-pw'];
        if (!input || !button) return;
        const show = input.type === 'password';
        input.type = show ? 'text' : 'password';
        button.setAttribute('aria-pressed', show ? 'true' : 'false');
        const label = show ? 'Ocultar contraseña' : 'Mostrar contraseña';
        button.setAttribute('aria-label', label);
        button.title = label;
    }

    function onClearPassword() {
        const input = E['pw-input'];
        if (!input) return;
        input.value = '';
        onPasswordInput();
        input.focus();
    }

    /* ------------------------------------------------------------- generador */

    // Charset por defecto: el mismo que usa el servidor para el alfabeto "web",
    // sin caracteres que se confunden entre sí (0/O, 1/l/I).
    const CHARSETS = {
        low: 'abcdefghijkmnopqrstuvwxyz',
        up: 'ABCDEFGHJKLMNPQRSTUVWXYZ',
        num: '23456789',
        sym: '!#$%&()*+,-./:;<=>?@^_'
    };

    function generateLocal(length) {
        const pool = CHARSETS.low + CHARSETS.up + CHARSETS.num + CHARSETS.sym;
        const out = [];
        for (let i = 0; i < length; i += 1) {
            const bytes = new Uint32Array(1);
            window.crypto.getRandomValues(bytes);
            out.push(pool[bytes[0] % pool.length]);
        }
        // Se garantiza una minúscula; el resto se completa al azar. Sin esto un
        // número largo puede salir sin minúsculas y ser rechazada por la regla.
        out[0] = CHARSETS.low[out[0].charCodeAt(0) % CHARSETS.low.length];
        out[length - 1] = CHARSETS.sym[out[length - 1].charCodeAt(0) % CHARSETS.sym.length];
        return out.join('');
    }

    function setGenStatus(text, state) {
        const node = E['gen-status'];
        if (!node) return;
        node.textContent = text;
        node.dataset.state = state || '';
    }

    function renderGenerated(password, note) {
        if (!E['gen-output']) return;
        E['gen-output'].value = password;
        const bits = round(password.length * Math.log2(CHARSETS.low.length + CHARSETS.up.length + CHARSETS.num.length + CHARSETS.sym.length), 1);
        setGenStatus(note + ' · ' + password.length + ' caracteres · ' + bits + ' bits', 'ok');
    }

    function doGenerate(event) {
        if (event) event.preventDefault();
        const length = Math.max(num(POLICY.data.min_length), num(E['gen-length'] && E['gen-length'].value) || 20);
        setGenStatus('Generando…', '');

        request('/api/generate', {
            method: 'POST',
            body: { length: length, alphabet: 'web', avoid_ambiguous: true, min_classes: 4 }
        }).then(function (body) {
            if (body && str(body.password)) {
                renderGenerated(str(body.password), 'Generada por el servidor');
            } else {
                renderGenerated(generateLocal(length), 'Generada en el navegador');
            }
        }).catch(function (err) {
            if (isAbort(err)) return;
            renderGenerated(generateLocal(length), 'Generada en el navegador (sin servidor)');
        });
    }

    function copyToClipboard(text) {
        if (window.isSecureContext && navigator.clipboard && navigator.clipboard.writeText) {
            return navigator.clipboard.writeText(text).then(
                function () { return true; },
                function () { return legacyCopy(text); }
            );
        }
        return Promise.resolve(legacyCopy(text));
    }

    function legacyCopy(text) {
        const area = document.createElement('textarea');
        area.value = text;
        area.setAttribute('readonly', '');
        area.style.position = 'fixed';
        area.style.top = '-1000px';
        document.body.appendChild(area);
        area.select();
        let ok = false;
        try { ok = document.execCommand('copy'); } catch (err) { ok = false; }
        document.body.removeChild(area);
        return ok;
    }

    function onCopyGenerated() {
        const value = E['gen-output'] ? E['gen-output'].value : '';
        if (!value) {
            setGenStatus('Primero genera una contraseña.', 'error');
            return;
        }
        copyToClipboard(value).then(function (ok) {
            setGenStatus(ok ? 'Copiada al portapapeles.' : 'No se pudo copiar.', ok ? 'ok' : 'error');
        });
    }

    function onUseGenerated() {
        const value = E['gen-output'] ? E['gen-output'].value : '';
        if (!value) {
            setGenStatus('Primero genera una contraseña.', 'error');
            return;
        }
        if (E['pw-input']) E['pw-input'].value = value;
        onPasswordInput();
        E['panel-analizador'] && E['panel-analizador'].scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    /* ------------------------------------------------------------- arranque */

    function refreshConnection() {
        if (!API_BASE) {
            // Sin apiBase no hay nada que consultar: se avisa de que el
            // veredicdo de la página es local.
            setConn('local', 'modo local · sin backend');
            showFallback('La página se sirve sin apiBase en config.js: todo lo que se ve es una estimación local.');
            return Promise.resolve(null);
        }
        return request('/api/health').then(function (body) {
            setConn('online', 'servidor en línea · v' + str(body && body.version));
            hideFallback();
            return body;
        }).catch(function () {
            setConn('local', 'sin conexión con el servidor');
            return null;
        });
    }

    function boot() {
        if (E['gen-form']) E['gen-form'].addEventListener('submit', doGenerate);
        if (E['btn-gen-copy']) E['btn-gen-copy'].addEventListener('click', onCopyGenerated);
        if (E['btn-gen-analyze']) E['btn-gen-analyze'].addEventListener('click', onUseGenerated);
        if (E['gen-length']) {
            E['gen-length'].addEventListener('input', function () {
                setText(E['gen-length-value'], str(E['gen-length'].value));
            });
        }
        if (E['pw-input']) {
            E['pw-input'].addEventListener('input', onPasswordInput);
            // El formulario no debe recargar la página: es una SPA de una carta.
            E['pw-input'].form && E['pw-input'].form.addEventListener('submit', function (ev) { ev.preventDefault(); });
        }
        if (E['btn-toggle-pw']) E['btn-toggle-pw'].addEventListener('click', onTogglePassword);
        if (E['btn-clear-pw']) E['btn-clear-pw'].addEventListener('click', onClearPassword);
        if (E['btn-retry']) E['btn-retry'].addEventListener('click', function () {
            if (E['pw-input'] && E['pw-input'].value) runAnalyze(E['pw-input'].value);
            else refreshConnection();
        });

        // La lista se pinta antes de pedir nada, con el espejo local. Si se
        // esperara a /api/policy, sin servidor la página arrancaría sin
        // requisitos y parecería vacía.
        reset();

        request('/api/policy').then(function (body) {
            // Si llegan las reglas del servidor, se vuelven a pintar: el
            // espejo deja de ser la fuente de la lista.
            if (normalizePolicy(body)) reset();
        }).catch(function () { /* se queda el espejo local */ });

        refreshConnection();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
}());
