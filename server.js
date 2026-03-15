const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8099;
const PASSWORD = process.env.AUTH_PASSWORD || null;
const COOKIE_NAME = 'vps_session';
const COOKIE_DOMAIN = '.5.161.182.15.nip.io';
const MAX_AGE_MS = 90 * 24 * 3600 * 1000;
const MAX_AGE_S = 90 * 24 * 3600;
const SESSIONS_FILE = path.join(__dirname, '.auth-sessions.json');

// Session store
let sessions = {};
try {
  if (fs.existsSync(SESSIONS_FILE)) {
    sessions = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'));
  }
} catch {}

function saveSessions() {
  try { fs.writeFileSync(SESSIONS_FILE, JSON.stringify(sessions)); } catch {}
}

function parseCookies(header) {
  const cookies = {};
  if (!header) return cookies;
  header.split(';').forEach(c => {
    const [k, ...v] = c.trim().split('=');
    if (k) cookies[k.trim()] = v.join('=').trim();
  });
  return cookies;
}

function isValid(req) {
  if (!PASSWORD) return true;
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies[COOKIE_NAME];
  if (!token) return false;
  const expiry = sessions[token];
  if (expiry && Date.now() < expiry) return true;
  delete sessions[token];
  saveSessions();
  return false;
}

function checkPassword(pw) {
  if (!PASSWORD || !pw) return false;
  return crypto.timingSafeEqual(
    crypto.createHash('sha256').update(pw).digest(),
    crypto.createHash('sha256').update(PASSWORD).digest()
  );
}

const LOGIN_HTML = (error, redirect) => `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0,viewport-fit=cover">
<title>Login</title><style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#1a1a2e;color:#e0e0e0;
min-height:100vh;display:flex;align-items:center;justify-content:center}
form{background:#16213e;border:1px solid #2a3a5c;border-radius:12px;padding:32px;width:300px;text-align:center}
h1{font-size:20px;color:#a0b4d0;margin-bottom:20px}
input{width:100%;padding:10px 12px;background:#0f1a2e;border:1px solid #2a3a5c;border-radius:6px;
color:#e0e0e0;font-size:16px;outline:none;margin-bottom:12px}
input:focus{border-color:#4a6fa5}
button{width:100%;padding:10px;background:#2a3a5c;color:#a0b4d0;border:none;border-radius:6px;
font-size:14px;cursor:pointer}button:hover{background:#3a4a6c}
.error{color:#e05555;font-size:13px;margin-bottom:12px}
</style></head><body>
<form method="POST" action="/auth/login${redirect ? '?rd=' + encodeURIComponent(redirect) : ''}">
<h1>Sign In</h1>
${error ? '<div class="error">Wrong password</div>' : ''}
<input type="password" name="password" placeholder="Password" autofocus>
<button type="submit">Log in</button>
</form></body></html>`;

app.use(express.urlencoded({ extended: false }));

// Auth check endpoint — Caddy forward_auth calls this
app.get('/auth/check', (req, res) => {
  if (isValid(req)) {
    res.setHeader('X-Auth-User', 'rachel');
    return res.sendStatus(200);
  }
  // Return 401 — Caddy will use handle_response to redirect
  res.sendStatus(401);
});

// Login page
app.get('/auth/login', (req, res) => {
  if (isValid(req)) {
    return res.redirect(303, req.query.rd || '/');
  }
  res.type('html').send(LOGIN_HTML(false, req.query.rd));
});

// Login POST
app.post('/auth/login', (req, res) => {
  const pw = req.body?.password || '';
  const redirect = req.query.rd || '/';

  if (checkPassword(pw)) {
    const token = crypto.randomBytes(32).toString('base64url');
    sessions[token] = Date.now() + MAX_AGE_MS;
    saveSessions();
    res.setHeader('Set-Cookie',
      `${COOKIE_NAME}=${token}; HttpOnly; SameSite=Lax; Max-Age=${MAX_AGE_S}; Path=/; Domain=${COOKIE_DOMAIN}; Secure`);
    return res.redirect(303, redirect);
  }
  res.type('html').send(LOGIN_HTML(true, req.query.rd));
});

// Logout
app.get('/auth/logout', (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies[COOKIE_NAME];
  if (token) {
    delete sessions[token];
    saveSessions();
  }
  res.setHeader('Set-Cookie',
    `${COOKIE_NAME}=; HttpOnly; SameSite=Lax; Max-Age=0; Path=/; Domain=${COOKIE_DOMAIN}; Secure`);
  res.redirect(303, '/auth/login');
});

if (!PASSWORD) console.log('WARNING: No AUTH_PASSWORD set, all requests will pass auth');
if (require.main === module) app.listen(PORT, '127.0.0.1', () => console.log(`Shared auth on :${PORT}`));

module.exports = { app, parseCookies, isValid, COOKIE_NAME };
