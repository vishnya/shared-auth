process.env.AUTH_PASSWORD = 'test-pw-123';

const http = require('http');
const assert = require('assert');
const { app, COOKIE_NAME } = require('./server');

const PORT = 18924;
let server, passed = 0, failed = 0, sessionCookie = null;

async function asyncTest(name, fn) {
  try { await fn(); passed++; console.log(`  PASS: ${name}`); }
  catch (e) { failed++; console.log(`  FAIL: ${name}\n        ${e.message}`); }
}

function request(method, urlPath, { body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const opts = { hostname: '127.0.0.1', port: PORT, path: urlPath, method, headers };
    if (body) {
      headers['Content-Type'] = headers['Content-Type'] || 'application/x-www-form-urlencoded';
      headers['Content-Length'] = Buffer.byteLength(body);
    }
    const req = http.request(opts, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data, cookies: res.headers['set-cookie'] }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function login() {
  const res = await request('POST', '/auth/login', { body: 'password=test-pw-123' });
  if (res.cookies) sessionCookie = res.cookies[0].split(';')[0];
  return res;
}

(async () => {
  server = http.createServer(app);
  await new Promise(r => server.listen(PORT, '127.0.0.1', r));

  try {
    console.log('\n=== Auth Check Tests ===\n');

    await asyncTest('/auth/check returns 401 without cookie', async () => {
      const res = await request('GET', '/auth/check');
      assert.strictEqual(res.status, 401);
    });

    await asyncTest('/auth/check returns 200 with valid cookie', async () => {
      await login();
      const res = await request('GET', '/auth/check', { headers: { Cookie: sessionCookie } });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.headers['x-auth-user'], 'rachel');
    });

    await asyncTest('/auth/check returns 401 with invalid cookie', async () => {
      const res = await request('GET', '/auth/check', { headers: { Cookie: `${COOKIE_NAME}=garbage` } });
      assert.strictEqual(res.status, 401);
    });

    console.log('\n=== Login Tests ===\n');

    await asyncTest('GET /auth/login shows login page', async () => {
      const res = await request('GET', '/auth/login');
      assert.strictEqual(res.status, 200);
      assert(res.body.includes('password'), 'Should have password field');
      assert(res.body.includes('Sign In'));
    });

    await asyncTest('wrong password shows error', async () => {
      const res = await request('POST', '/auth/login', { body: 'password=wrong' });
      assert.strictEqual(res.status, 200);
      assert(res.body.includes('Wrong password'));
    });

    await asyncTest('correct password sets cookie and redirects', async () => {
      const res = await login();
      assert.strictEqual(res.status, 303);
      assert(res.cookies, 'Should set cookie');
      const c = res.cookies[0];
      assert(c.includes(`${COOKIE_NAME}=`), 'Cookie name');
      assert(c.includes('HttpOnly'), 'HttpOnly');
      assert(c.includes('SameSite=Lax'), 'SameSite=Lax for mobile Chrome');
      assert(!c.includes('SameSite=Strict'), 'Must NOT be Strict');
      assert(c.includes('Domain=.5.161.182.15.nip.io'), 'Cookie on parent domain');
    });

    await asyncTest('cookie has 90-day Max-Age', async () => {
      const res = await login();
      const m = res.cookies[0].match(/Max-Age=(\d+)/);
      assert(m, 'Max-Age present');
      const age = parseInt(m[1]);
      assert(age >= 89 * 86400 && age <= 91 * 86400, `Should be ~30 days, got ${age}s`);
    });

    await asyncTest('login with redirect param redirects to target', async () => {
      const res = await request('POST', '/auth/login?rd=https://code.5.161.182.15.nip.io/', { body: 'password=test-pw-123' });
      assert.strictEqual(res.status, 303);
      assert.strictEqual(res.headers.location, 'https://code.5.161.182.15.nip.io/');
    });

    await asyncTest('already authenticated skips login page', async () => {
      await login();
      const res = await request('GET', '/auth/login', { headers: { Cookie: sessionCookie } });
      assert.strictEqual(res.status, 303);
    });

    console.log('\n=== Logout Tests ===\n');

    await asyncTest('logout clears cookie and redirects', async () => {
      await login();
      const res = await request('GET', '/auth/logout', { headers: { Cookie: sessionCookie } });
      assert.strictEqual(res.status, 303);
      assert(res.cookies[0].includes('Max-Age=0'), 'Cookie should be cleared');
      // Verify cookie no longer works
      const check = await request('GET', '/auth/check', { headers: { Cookie: sessionCookie } });
      assert.strictEqual(check.status, 401);
    });

    console.log('\n=== Cookie Persistence Tests ===\n');

    await asyncTest('cookie works across multiple sequential requests', async () => {
      await login();
      for (let i = 0; i < 5; i++) {
        const res = await request('GET', '/auth/check', { headers: { Cookie: sessionCookie } });
        assert.strictEqual(res.status, 200, `Request ${i + 1} should pass`);
      }
    });

  } finally {
    server.close();
  }

  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
  process.exit(failed > 0 ? 1 : 0);
})();
