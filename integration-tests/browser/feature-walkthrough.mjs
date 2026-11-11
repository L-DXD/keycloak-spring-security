// 기능별 손 확인: 실제 브라우저(Chromium) + bootRun으로 띄운 샘플 앱 두 벌 + Docker로 띄운 Keycloak·PostgreSQL·화면.
// E2E(e2eTest)가 같은 시나리오를 HTTP 클라이언트로 자동으로 본다면, 이 스크립트는 사람이 쓰는 모습 그대로 브라우저로 한 번 더 본다.
// Gradle 빌드에 묶지 않는다. 라이브러리를 크게 바꿨을 때와 배포 전에 돌린다 (docs/v3/03-검증-환경.md 4-2절).
//
// 준비 (저장소 루트에서):
//   integration-tests/local-stack.sh up
//   ./gradlew :integration-tests:servlet-app:bootRun > integration-tests/servlet-app/build/demo.log                                        # 다른 창
//   ./gradlew :integration-tests:servlet-app:bootRun --args=--spring.profiles.active=demo2 > integration-tests/servlet-app/build/demo2.log  # 다른 창
// 실행:
//   KSS_DEMO_LOG=integration-tests/servlet-app/build/demo.log KSS_DEMO2_LOG=integration-tests/servlet-app/build/demo2.log node integration-tests/browser/feature-walkthrough.mjs [--slow] [--no-outage] [--no-logs]
//     --slow       실제 시간을 기다리는 것까지 (at 만료 뒤 95초, Client Session Idle 2분, 절대 상한 3분. 같이 돌려 약 3분 30초)
//     --no-outage  Keycloak 컨테이너를 잠깐 멈춰 보는 것(REFRESH-06)을 건너뛴다
//     --no-logs    두 앱의 로그 파일 없이 돌린다. 감사 로그 사유와 "로그에 토큰이 없다"는 보지 않는다
//   KSS_DEMO_LOG·KSS_DEMO2_LOG는 --no-logs가 아니면 꼭 주고, 파일이 있어야 한다(없으면 시작하지 않는다).
//   건너뛴 확인은 SKIP으로 따로 센다(통과로 세지 않는다).
//   KSS_REPORT=<파일>을 주면 결과표를 Markdown으로 쓴다.
//   Playwright 1.43 이상이 필요하다(쿠키 하나만 지우는 clearCookies 필터).
//   모든 주소가 이 PC 안이다. HTTPS_PROXY 같은 프록시 환경 변수가 있으면 지우고 돌린다(브라우저가 그 프록시로 보낸다).
//
// 값은 모두 테스트 값이다(realm-kss-demo.json, compose.yaml). 이 스크립트는 임시 사용자를 만들고 끝나면 지운다.
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import crypto from 'node:crypto';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { chromium } from 'playwright';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const COMPOSE = path.join(ROOT, 'compose.yaml');
const TLS_DIR = process.env.KSS_TLS_DIR ?? path.join(ROOT, 'servlet-app/build/e2e/tls');
const SLOW = process.argv.includes('--slow');
const OUTAGE = !process.argv.includes('--no-outage');
const LOGS = !process.argv.includes('--no-logs');

const APP = 'https://app.kss.test';
const SAME_SITE_OTHER = 'https://evil.kss.test'; // 화면과 같은 사이트, 다른 origin
const CROSS_SITE = 'https://evil.test'; // 다른 사이트
const KC = 'http://sso.kss.test:8180';
const REALM = 'kss-demo';
const APPS = {
  demo: { api: 'https://api.kss.test:8443', schema: 'public', log: process.env.KSS_DEMO_LOG },
  demo2: { api: 'https://api.kss.test:8444', schema: 'demo2', log: process.env.KSS_DEMO2_LOG },
};
const ALICE = { username: 'alice', password: 'alice-test-password' };
const AT_SECONDS = 60; // 테스트 realm: 액세스 토큰 60초
const ABSOLUTE_SECONDS = 180; // 샘플 앱 테스트 설정: 절대 상한 3분
const IDLE_SECONDS = 120; // 테스트 realm: Client Session Idle 2분

// ---------------------------------------------------------------- 결과

const results = [];
const trace = (m) => process.env.KSS_TRACE && console.error(`[${new Date().toISOString().slice(11, 19)}] ${m}`);
const LABEL = { pass: 'PASS', fail: 'FAIL', skip: 'SKIP' };
// ok가 null이면 건너뜀(SKIP). 통과로 세지 않는다
function check(id, scenario, name, ok, detail = '') {
  const state = ok === null ? 'skip' : ok ? 'pass' : 'fail';
  results.push({ id, scenario, name, state, detail: String(detail) });
  console.log(`${LABEL[state]} ${id} [${scenario}] ${name}${detail ? ' — ' + detail : ''}`);
}
function section(title) {
  console.log(`\n== ${title}`);
  results.push({ section: title });
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, { timeoutMs = 10_000, everyMs = 250 } = {}) {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const v = await fn();
    if (v || Date.now() > end) return v;
    await sleep(everyMs);
  }
}

// ---------------------------------------------------------------- 시작 전 검사

if (LOGS) {
  const missing = Object.entries(APPS).filter(([, a]) => !a.log || !fs.existsSync(a.log)).map(([n, a]) => `${n}: ${a.log ?? '(KSS_DEMO_LOG·KSS_DEMO2_LOG 안 줌)'}`);
  if (missing.length) {
    console.error(`앱 로그 파일이 없습니다 (${missing.join(', ')}). bootRun 출력을 파일로 받아 그 경로를 주거나, 로그 없이 돌리려면 --no-logs를 줍니다`);
    process.exit(2);
  }
}
{
  const [major, minor] = createRequire(import.meta.url)('playwright/package.json').version.split('.').map(Number);
  if (major < 1 || (major === 1 && minor < 43)) {
    console.error('Playwright 1.43 이상이 필요합니다(clearCookies 필터). 지금 판에서는 쿠키를 모두 지워 확인이 엉뚱하게 실패합니다');
    process.exit(2);
  }
}

// ---------------------------------------------------------------- Node 쪽 HTTP (*.kss.test를 이 PC로)

const ca = fs.readFileSync(path.join(TLS_DIR, 'ca.pem'));
function lookup(hostname, options, callback) {
  if (hostname.endsWith('.kss.test') || hostname === 'evil.test') {
    return options && options.all ? callback(null, [{ address: '127.0.0.1', family: 4 }]) : callback(null, '127.0.0.1', 4);
  }
  return dns.lookup(hostname, options, callback);
}
function request(url, { method = 'GET', headers = {}, body } = {}) {
  const u = new URL(url);
  const lib = u.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    const req = lib.request(u, { method, headers, lookup, ca, agent: false }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.setTimeout(15_000, () => req.destroy(new Error(`응답 없음 15초: ${method} ${url}`)));
    if (body) req.write(body);
    req.end();
  });
}
const form = (o) => new URLSearchParams(o).toString();
const json = (t) => { try { return JSON.parse(t); } catch { return null; } };

// ---------------------------------------------------------------- Keycloak 관리 API (테스트 관리자 admin/admin)

async function admin(pathAndQuery, { method = 'GET', body } = {}) {
  const token = json((await request(`${KC}/realms/master/protocol/openid-connect/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form({ grant_type: 'password', client_id: 'admin-cli', username: 'admin', password: 'admin' }),
  })).text).access_token;
  const res = await request(`${KC}/admin/realms/${REALM}${pathAndQuery}`, {
    method, headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, body: json(res.text) };
}
async function userId(username) {
  return (await admin(`/users?username=${encodeURIComponent(username)}&exact=true`)).body[0].id;
}
async function createUser(username, password) {
  await admin('/users', { method: 'POST', body: {
    username, enabled: true, emailVerified: true, firstName: 'Walk', lastName: 'Test', email: `${username}@example.test`,
    credentials: [{ type: 'password', value: password, temporary: false }],
  } });
  return userId(username);
}
const kcSessions = async (id) => (await admin(`/users/${id}/sessions`)).body ?? [];
// 이 Keycloak 세션(kc_sid)에서 since(ms) 뒤에 생긴 사용자 이벤트
async function kcEvents(kcSid, since, type) {
  const day = new Date(since).toISOString().slice(0, 10);
  const events = (await admin(`/events?max=1000&dateFrom=${day}${type ? `&type=${type}` : ''}`)).body ?? [];
  return events.filter((e) => e.sessionId === kcSid && e.time >= since);
}

// 이 client의 갱신 이벤트(성공·실패 모두). 세션 id가 비어 있는 실패 이벤트도 잡는다
async function kcRefreshEvents(clientId, since) {
  const day = new Date(since).toISOString().slice(0, 10);
  const events = (await admin(`/events?max=1000&client=${clientId}&dateFrom=${day}`)).body ?? [];
  return events.filter((e) => e.time >= since && e.type.startsWith('REFRESH_TOKEN'));
}

// ---------------------------------------------------------------- DB (compose의 postgres 컨테이너에 psql)

function sql(query) {
  return execFileSync('docker', ['compose', '-f', COMPOSE, 'exec', '-T', 'postgres', 'psql', '-U', 'kss', '-d', 'kss', '-tA', '-F', '|', '-c', query],
    { encoding: 'utf8' }).trim();
}
// 이 브라우저(context)의 세션 행. 행은 sid 쿠키의 SHA-256(sid_hash)으로 찾는다(다른 실행이 남긴 행과 섞이지 않게)
const sidHash = (sid) => crypto.createHash('sha256').update(sid, 'ascii').digest('hex');
function rowWhere(app, where) {
  const out = sql(`select id, sid_hash, kc_sid, keycloak_user_id, encode(refresh_token_enc, 'escape') like 'eyJ%', refreshed_at
                   from ${APPS[app].schema}.auth_session where ${where}`);
  if (!out) return null;
  const [id, sidHashValue, kcSid, keycloakUserId, plain, refreshedAt] = out.split('\n')[0].split('|');
  return { id, sidHash: sidHashValue, kcSid, keycloakUserId, plain: plain === 't', refreshedAt };
}
async function myRow(context, app) {
  const sid = await cookie(context, app, 'sid');
  return sid ? rowWhere(app, `sid_hash = '${sidHash(sid.value)}'`) : null;
}
const rowExists = (app, id) => rowWhere(app, `id = '${id}'`) !== null;

// ---------------------------------------------------------------- 로그

function appLog(app) {
  const file = APPS[app].log;
  return file && fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null;
}
// 감사 로그 한 줄을 기다린다(bootRun 출력은 Gradle을 거쳐 조금 늦게 파일에 써진다). --no-logs면 null(안 봄)
async function auditLine(app, text) {
  if (!LOGS) return null;
  return waitFor(() => appLog(app).split('\n').some((l) => l.includes(text)), { timeoutMs: 5_000 });
}
const auditEnded = (app, reason, sessionId) => auditLine(app, `[KSS] 세션 끝남 reason=${reason} session=${sessionId}`);
const shown = (v) => (v === null ? '안 봄(--no-logs)' : v ? '있음' : '없음');

// ---------------------------------------------------------------- 브라우저

const browser = await chromium.launch({
  // 주소(origin)는 그대로 두고 연결만 이 PC로 보낸다. 포트는 바꾸지 않는다
  args: ['--host-resolver-rules=MAP *.kss.test 127.0.0.1, MAP evil.test 127.0.0.1'],
});
// 이번 실행에서 앱이 내린 sid 쿠키 값 전부(W-40: 로그에 원문이 없어야 한다). 302 응답의 Set-Cookie도 본다
const seenSids = new Set();
function watchSids(context) {
  context.on('response', async (response) => {
    try {
      for (const h of await response.headersArray()) {
        const m = h.name.toLowerCase() === 'set-cookie' && /^__Host-[A-Za-z0-9-]+_sid=([^;]+)/.exec(h.value);
        if (m) seenSids.add(m[1]);
      }
    } catch { /* 페이지가 닫히며 끊긴 응답은 넘긴다 */ }
  });
}
// 테스트 CA는 브라우저가 모르므로 인증서 오류만 넘긴다. https 주소라서 Secure·__Host- 규칙은 그대로 적용된다
const newContext = async () => {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  watchSids(context);
  return context;
};

// Keycloak 컨테이너를 멈춘 동안 무슨 일이 생겨도 다시 띄운다(설정이 달라도 컨테이너를 새로 만들지 않는다: realm이 처음 상태로 돌아가지 않게)
let keycloakStopped = false;
function stopKeycloak() {
  keycloakStopped = true;
  execFileSync('docker', ['compose', '-f', COMPOSE, 'stop', 'keycloak'], { stdio: 'ignore' });
}
function startKeycloak() {
  execFileSync('docker', ['compose', '-f', COMPOSE, 'up', '-d', '--wait', '--no-recreate', 'keycloak'], { stdio: 'ignore' });
  keycloakStopped = false;
}

const apiUrl = (app, p) => `${APPS[app].api}${p}`;
async function cookiesOf(context, app) {
  return (await context.cookies('https://api.kss.test')).filter((c) => c.name.startsWith(`__Host-${app}_`));
}
const cookie = async (context, app, kind) => (await cookiesOf(context, app)).find((c) => c.name === `__Host-${app}_${kind}`);
async function dropAt(context, app) {
  await context.clearCookies({ name: `__Host-${app}_at` });
}
const jwtPayload = (t) => JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString('utf8'));

// 화면(app.kss.test) 페이지 안에서 fetch (credentials 포함)
async function frontFetch(page, url, init = {}) {
  return page.evaluate(async ({ url, init }) => {
    try {
      const r = await fetch(url, { credentials: 'include', ...init });
      const text = await r.text();
      return { status: r.status, text };
    } catch (e) {
      return { status: 0, error: `${e.name}: ${e.message}` };
    }
  }, { url, init });
}
async function frontCsrf(page, app) {
  return json((await frontFetch(page, apiUrl(app, '/api/csrf'))).text)?.token;
}

// 누르고 화면 이동이 끝날 때까지 기다린다(302는 건너뛰고 실제로 열린 페이지 하나). 같은 주소로 돌아와도 기다린다
async function clickAndLand(page, selector) {
  await Promise.all([page.waitForEvent('framenavigated', (f) => f === page.mainFrame()), page.click(selector)]);
  await page.waitForLoadState('load');
}

// 이 페이지에서 HTML 폼을 만들어 POST한다(최상위 이동). 응답과, 그 응답으로 화면 이동이 끝나기를 함께 기다린다
async function submitForm(page, url, fields) {
  const [response] = await Promise.all([
    page.waitForResponse((r) => r.url() === url && r.request().method() === 'POST'),
    page.waitForEvent('framenavigated', (f) => f === page.mainFrame()),
    page.evaluate(({ url, fields }) => {
      const f = document.createElement('form');
      f.method = 'POST';
      f.action = url;
      for (const [name, value] of Object.entries(fields)) {
        const input = document.createElement('input');
        input.name = name;
        input.value = value;
        f.appendChild(input);
      }
      document.body.appendChild(f);
      f.submit();
    }, { url, fields }),
  ]);
  await page.waitForLoadState('load');
  return { status: response.status(), cookie: (await response.request().allHeaders())['cookie'] ?? '' };
}

// 화면의 "로그인" 버튼으로 로그인한다. Keycloak 로그인 폼이 나오면 채운다. 폼이 나왔는지 돌려준다
async function loginFromFront(page, app, user, { from = '/' } = {}) {
  await page.goto(`${APP}${from}`);
  await clickAndLand(page, `#${app}-login`);
  let formShown = false;
  if (new URL(page.url()).origin === KC) {
    formShown = true;
    await page.fill('#username', user.username);
    await page.fill('#password', user.password);
    await Promise.all([page.waitForURL((u) => u.origin === APP), page.click('#kc-login')]);
  }
  return formShown;
}

const tempUsers = [];
let exitCode = 0;
let abortedBy = null;
// Ctrl+C: Keycloak을 다시 띄우고 임시 사용자를 지운 뒤 끝낸다
process.once('SIGINT', async () => {
  console.error('\n멈춤 요청을 받았습니다. Keycloak·임시 사용자를 정리합니다');
  if (keycloakStopped) { try { startKeycloak(); } catch { /* 손으로 local-stack.sh up */ } }
  for (const id of tempUsers) { try { await admin(`/users/${id}`, { method: 'DELETE' }); } catch { /* 넘긴다 */ } }
  process.exit(130);
});
try {
  const aliceId = await userId(ALICE.username);
  const page = await (async () => { const ctx = await newContext(); return ctx.newPage(); })();
  const ctx = page.context();

  // ============================================================ 1. 로그인 전
  section('1. 로그인 전 (화면에서 부름)');
  await page.goto(`${APP}/`);
  const ping = await frontFetch(page, apiUrl('demo', '/api/public/ping'));
  check('W-01', 'REQ-02', '로그인 없이 허용된 주소는 200', ping.status === 200, `${ping.status} ${ping.text}`);
  const me0 = await frontFetch(page, apiUrl('demo', '/api/me'));
  const me0Body = json(me0.text) ?? {};
  check('W-02', 'LOGIN-01', '로그인 전 /api/me는 401 JSON(오류 코드 + 로그인 주소)',
    me0.status === 401 && me0Body.code === 'AUTHENTICATION_REQUIRED' && me0Body.loginUrl === '/oauth2/authorization/keycloak', `${me0.status} ${me0.text}`);
  const node401 = await request(apiUrl('demo', '/api/me'));
  check('W-03', 'EVT-03', '인증에 실패한 응답에도 X-Request-Id가 있다', Boolean(node401.headers['x-request-id']), node401.headers['x-request-id'] ?? '없음');

  // ============================================================ 2. 로그인
  section('2. 로그인 (화면 버튼 → Keycloak 로그인 폼 → 화면)');
  const authorizeRequest = page.waitForRequest((r) => r.url().startsWith(`${KC}/realms/${REALM}/protocol/openid-connect/auth`));
  const loginStart = Date.now();
  const formShown = await loginFromFront(page, 'demo', ALICE, { from: '/items/3' });
  const authorize = new URL((await authorizeRequest).url());
  const q = Object.fromEntries(authorize.searchParams);
  check('W-04', 'LOGIN-02', 'Keycloak 인가 요청에 PKCE S256, state, nonce, scope=openid',
    q.code_challenge_method === 'S256' && q.code_challenge && q.state && q.nonce && (q.scope ?? '').split(' ').includes('openid'),
    `client_id=${q.client_id} method=${q.code_challenge_method} scope=${q.scope}`);
  check('W-05', 'LOGIN-03 · E2E-04', 'Keycloak 로그인 폼을 채우면 화면의 돌아갈 경로(/items/3)로 온다',
    formShown && page.url() === `${APP}/items/3`, page.url());

  const demoCookies = await cookiesOf(ctx, 'demo');
  const names = demoCookies.map((c) => c.name).sort();
  check('W-06', 'COOKIE-01 · 02', '쿠키는 sid·at·csrf 셋뿐(login 쿠키는 지워짐, ID 토큰·JSESSIONID 없음)',
    JSON.stringify(names) === JSON.stringify(['__Host-demo_at', '__Host-demo_csrf', '__Host-demo_sid'])
      && !(await ctx.cookies('https://api.kss.test')).some((c) => /JSESSIONID|id_token|access_token/i.test(c.name)), names.join(', '));
  check('W-07', 'COOKIE-01', '세 쿠키 모두 Secure·HttpOnly·SameSite=Lax·Path=/·이 호스트 전용',
    demoCookies.every((c) => c.secure && c.httpOnly && c.sameSite === 'Lax' && c.path === '/' && c.domain === 'api.kss.test'),
    demoCookies.map((c) => `${c.name.replace('__Host-demo_', '')}:${c.secure}/${c.httpOnly}/${c.sameSite}/${c.path}/${c.domain}`).join(' '));
  const now = Date.now() / 1000;
  const at = demoCookies.find((c) => c.name.endsWith('_at'));
  const sid = demoCookies.find((c) => c.name.endsWith('_sid'));
  const csrfCookie = demoCookies.find((c) => c.name.endsWith('_csrf'));
  // expires가 -1이면 수명 없는 쿠키(브라우저를 닫을 때까지)라 실패여야 한다 → 아래 한계도 본다
  const lifeOk = (c, max) => c.expires > now && c.expires - now <= max + 2;
  check('W-08', 'COOKIE-03', '세 쿠키 모두 수명(Max-Age)이 있고, at ≤ 토큰 남은 시간(60초), sid·csrf ≤ 절대 상한(3분)',
    lifeOk(at, AT_SECONDS) && lifeOk(sid, ABSOLUTE_SECONDS) && lifeOk(csrfCookie, ABSOLUTE_SECONDS),
    `at ${Math.round(at.expires - now)}초, sid ${Math.round(sid.expires - now)}초, csrf ${Math.round(csrfCookie.expires - now)}초`);
  seenSids.add(sid.value);
  const row1 = await myRow(ctx, 'demo');
  check('W-09', 'LOGIN-03 · STORE-01', 'DB에 이 브라우저의 세션 행이 생긴다. sid는 해시(64자)로만, 리프레시 토큰은 암호문으로만 있다',
    row1 && row1.keycloakUserId === aliceId && /^[0-9a-f]{64}$/.test(row1.sidHash) && row1.sidHash !== sid.value && !row1.plain,
    row1 ? `행 ${row1.id}` : '행 없음');
  // 쿠키가 붙는 API 주소의 페이지에서 본다(화면 주소에서는 HttpOnly가 아니어도 원래 안 보이므로)
  const back = page.url();
  await page.goto(apiUrl('demo', '/api/public/ping'));
  const visible = await page.evaluate(() => document.cookie);
  await page.goto(back);
  check('W-10', 'COOKIE-01', 'API 주소의 스크립트(document.cookie)도 앱 쿠키를 못 읽는다(HttpOnly)', !visible.includes('__Host-'), JSON.stringify(visible));
  const me1 = await frontFetch(page, apiUrl('demo', '/api/me'));
  const me1Body = json(me1.text) ?? {};
  check('W-11', 'REQ-01', '화면에서 /api/me 200, 로그인한 사람(alice)', me1.status === 200 && me1Body.username === 'alice' && me1Body.sub === aliceId,
    `${me1.status} ${me1.text}`);
  const created = await auditLine('demo', `[KSS] 세션 만듦 session=${row1?.id}`);
  check('W-12', 'EVT-01', '세션 만듦 감사 로그가 남는다', created === null ? null : created, shown(created));

  // ============================================================ 3. 돌아갈 주소 검사, 다시 로그인
  section('3. 돌아갈 주소 검사 · 다시 로그인');
  for (const evilReturn of ['https://evil.example/steal', '//evil.example/steal', '/\\evil.example']) {
    const t = await ctx.newPage();
    // 라이브러리가 바깥 주소로 보내면 이동이 실패하거나(.example은 없는 이름) 다른 곳에 닿는다 → 멈추지 않고 실패로 적는다
    const outside = [];
    t.on('request', (r) => { const o = new URL(r.url()).origin; if (o !== APP && o !== KC && o !== APPS.demo.api) outside.push(r.url()); });
    let landed;
    try {
      await Promise.all([
        t.waitForURL((u) => u.origin === APP || u.origin === KC, { timeout: 15_000 }),
        t.goto(`${APPS.demo.api}/oauth2/authorization/keycloak?return=${encodeURIComponent(evilReturn)}`),
      ]);
      landed = t.url();
    } catch (e) {
      landed = `이동 실패: ${String(e.message).split('\n')[0]}`;
    }
    check('W-13', 'LOGIN-04', `돌아갈 주소 ${evilReturn} → 화면 첫 주소(/)로만 간다 (Keycloak은 이미 로그인돼 폼 없음)`,
      landed === `${APP}/` && outside.length === 0, outside.length ? `바깥 요청 ${outside[0]}` : landed);
    await t.close();
  }
  const sidAfter = await cookie(ctx, 'demo', 'sid');
  const row2 = await myRow(ctx, 'demo');
  seenSids.add(sidAfter.value);
  const relogin = await auditEnded('demo', 'relogin', row1.id);
  check('W-14', 'LOGIN-06', '예전 sid 쿠키가 있는 채로 다시 로그인하면 새 sid가 나오고 예전 행은 지워진다(사유 relogin)',
    sidAfter.value !== sid.value && row2 && row2.id !== row1.id && !rowExists('demo', row1.id) && relogin !== false, `감사 로그 ${shown(relogin)}`);

  // ============================================================ 4. CSRF · Origin · CORS
  section('4. CSRF · Origin · CORS');
  await page.goto(`${APP}/`);
  const token = await frontCsrf(page, 'demo');
  const post = await frontFetch(page, apiUrl('demo', '/api/items'), {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-XSRF-TOKEN': token }, body: JSON.stringify({ name: 'walk' }),
  });
  check('W-15', 'CSRF-01 · 03 · CORS-01', '화면에서 /api/csrf 토큰을 X-XSRF-TOKEN으로 보내면 POST 201 (사전 확인 통과)',
    post.status === 201 && json(post.text)?.createdBy === aliceId, `${post.status} ${post.text}`);
  const noToken = await frontFetch(page, apiUrl('demo', '/api/items'), {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
  });
  check('W-16', 'CSRF-02', '토큰 없는 POST는 403 INVALID_CSRF_TOKEN', noToken.status === 403 && json(noToken.text)?.code === 'INVALID_CSRF_TOKEN',
    `${noToken.status} ${noToken.text}`);
  // 화면의 HTML 폼(최상위 이동)으로 숨은 칸 _csrf
  const formPost = await submitForm(page, apiUrl('demo', '/api/items'), { _csrf: await frontCsrf(page, 'demo'), name: 'form' });
  check('W-17', 'CSRF-07', '화면 HTML 폼의 숨은 칸 _csrf로 POST 201', formPost.status === 201, String(formPost.status));

  // 같은 사이트의 다른 화면(evil.kss.test): SameSite=Lax로는 쿠키가 가지만 Origin 확인이 막는다
  const sameSite = await ctx.newPage();
  await sameSite.goto(`${SAME_SITE_OTHER}/`);
  const leaked = await frontCsrf(page, 'demo'); // 토큰이 새 나갔다고 치고 넣어 본다
  const sameSitePost = await submitForm(sameSite, apiUrl('demo', '/api/items'), { _csrf: leaked, name: 'same-site' });
  const sameSiteCookie = sameSitePost.cookie;
  check('W-18', 'CSRF-05', '같은 사이트의 다른 화면(evil.kss.test) 폼 POST: 쿠키와 맞는 토큰이 가도 Origin 확인이 403',
    sameSitePost.status === 403 && sameSiteCookie.includes('__Host-demo_sid'), `status ${sameSitePost.status}, 쿠키 ${sameSiteCookie.includes('__Host-demo_sid') ? '감' : '안 감'}`);
  await sameSite.goto(`${SAME_SITE_OTHER}/`); // 폼 POST로 API 주소로 넘어갔으므로 다시 그 화면으로
  const sameSiteFetch = await frontFetch(sameSite, apiUrl('demo', '/api/me'));
  check('W-19', 'CORS-02', '같은 사이트의 다른 화면에서 fetch는 CORS로 막힌다', sameSiteFetch.status === 0, sameSiteFetch.error ?? sameSiteFetch.status);
  await sameSite.close();

  const cross = await ctx.newPage();
  await cross.goto(`${CROSS_SITE}/`);
  const crossFetch = await frontFetch(cross, apiUrl('demo', '/api/me'));
  check('W-20', 'CORS-02', '다른 사이트(evil.test)에서 fetch는 CORS로 막힌다', crossFetch.status === 0, crossFetch.error ?? crossFetch.status);
  const crossPost = await submitForm(cross, apiUrl('demo', '/api/items'), { name: 'cross-site' });
  const crossCookie = crossPost.cookie;
  check('W-21', 'CSRF-05', '다른 사이트의 폼 POST에는 앱 쿠키가 안 가고(SameSite=Lax) 403', crossPost.status === 403 && !crossCookie.includes('__Host-'),
    `status ${crossPost.status}, 쿠키 ${crossCookie ? '감' : '안 감'}`);
  await cross.close();
  trace('사전 확인 요청');
  const preflightGood = await request(apiUrl('demo', '/api/items'), { method: 'OPTIONS', headers: {
    Origin: APP, 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type,x-xsrf-token' } });
  const preflightBad = await request(apiUrl('demo', '/api/items'), { method: 'OPTIONS', headers: {
    Origin: SAME_SITE_OTHER, 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type,x-xsrf-token' } });
  check('W-22', 'CORS-01 · 02', '사전 확인: 화면 Origin만 허용(자격 증명 포함), 다른 Origin에는 허용 헤더가 없다',
    preflightGood.headers['access-control-allow-origin'] === APP && preflightGood.headers['access-control-allow-credentials'] === 'true'
      && /x-xsrf-token/i.test(preflightGood.headers['access-control-allow-headers'] ?? '') && !preflightBad.headers['access-control-allow-origin'],
    `화면 ${preflightGood.headers['access-control-allow-origin']}, 다른 곳 ${preflightBad.headers['access-control-allow-origin'] ?? '없음'}`);

  // ============================================================ 5. 로그아웃 주소의 막힌 길
  section('5. 로그아웃 주소의 막힌 길');
  const [getLogout] = await Promise.all([page.waitForResponse((r) => r.url() === apiUrl('demo', '/logout')), page.goto(apiUrl('demo', '/logout'))]);
  const getLogoutHeaders = await getLogout.allHeaders();
  check('W-23', 'LOGOUT-03', 'GET /logout은 405(Allow: POST)이고 로그아웃되지 않는다',
    getLogout.status() === 405 && getLogoutHeaders['allow'] === 'POST' && (await myRow(ctx, 'demo')) !== null, `${getLogout.status()} Allow=${getLogoutHeaders['allow']}`);
  await page.goto(`${APP}/`);
  const logoutNoCsrf = await frontFetch(page, apiUrl('demo', '/logout'), { method: 'POST' });
  check('W-24', 'LOGOUT-04', 'CSRF 없이 POST /logout은 403, 세션 그대로',
    logoutNoCsrf.status === 403 && (await myRow(ctx, 'demo')) !== null, `${logoutNoCsrf.status}`);

  // ============================================================ 6. 요청 인증 · 갱신
  section('6. 요청 인증 · 갱신');
  let since = Date.now();
  const kcSid = (await myRow(ctx, 'demo')).kcSid;
  for (let i = 0; i < 20; i++) await frontFetch(page, apiUrl('demo', '/api/me'));
  await sleep(500);
  const callsWhileValid = await kcEvents(kcSid, since);
  check('W-25', 'JWT-09', 'at가 살아 있는 동안 /api/me 20번: Keycloak 토큰·검사·사용자 정보 호출 0번(Keycloak 이벤트)',
    callsWhileValid.length === 0, `이벤트 ${callsWhileValid.map((e) => e.type).join(',') || '없음'}`);

  const rowBefore = await myRow(ctx, 'demo');
  const atBefore = (await cookie(ctx, 'demo', 'at')).value;
  await dropAt(ctx, 'demo'); // 브라우저가 Max-Age 지난 at 쿠키를 버린 것과 같다
  const refreshed = await frontFetch(page, apiUrl('demo', '/api/me'));
  const rowAfter = await myRow(ctx, 'demo');
  const atAfter = await cookie(ctx, 'demo', 'at');
  check('W-26', 'REFRESH-01', 'at 쿠키가 없어지면(만료) 다음 요청이 그대로 200, 새 at 쿠키, 행의 refreshed_at이 바뀐다',
    refreshed.status === 200 && atAfter && atAfter.value !== atBefore && rowAfter.refreshedAt && rowAfter.refreshedAt !== rowBefore.refreshedAt,
    `${refreshed.status}, refreshed_at ${rowAfter.refreshedAt}`);

  await sleep(11_000); // 바로 앞 갱신의 재사용 시간(refresh-reuse-window 10초)을 넘긴다
  await dropAt(ctx, 'demo');
  since = Date.now();
  const concurrent = await page.evaluate(async (url) => {
    const rs = await Promise.all(Array.from({ length: 5 }, () => fetch(url, { credentials: 'include' }).then((r) => r.status)));
    return rs;
  }, apiUrl('demo', '/api/me'));
  await sleep(500);
  const refreshEvents = await kcEvents(kcSid, since, 'REFRESH_TOKEN');
  check('W-27', 'REFRESH-02', '만료 상태에서 같은 사람이 동시에 5번 부르면 모두 200, Keycloak 갱신은 1번',
    concurrent.every((s) => s === 200) && refreshEvents.length === 1, `${concurrent.join(',')} / 갱신 ${refreshEvents.length}번`);

  await dropAt(ctx, 'demo');
  const background = await frontFetch(page, apiUrl('demo', '/api/me'), { headers: { 'X-Background': '1' } });
  const afterBackground = await frontFetch(page, apiUrl('demo', '/api/me'));
  check('W-28', 'REFRESH-07', 'X-Background: 1 요청은 갱신하지 않고 401, 행은 그대로. 사람이 부른 다음 요청은 200',
    background.status === 401 && afterBackground.status === 200 && (await myRow(ctx, 'demo')) !== null, `${background.status} → ${afterBackground.status}`);

  if (OUTAGE) {
    // 방금(10초 안에) 갱신한 세션은 그 결과를 다시 쓰므로(refresh-reuse-window 기본 10초) 그 시간을 넘긴 뒤 멈춘다
    await sleep(11_000);
    let down, downBody, rowDuring;
    stopKeycloak();
    try {
      await dropAt(ctx, 'demo');
      down = await frontFetch(page, apiUrl('demo', '/api/me'));
      downBody = json(down.text) ?? {};
      rowDuring = await myRow(ctx, 'demo');
    } finally {
      startKeycloak();
    }
    const up = await frontFetch(page, apiUrl('demo', '/api/me'));
    check('W-29', 'REFRESH-06', 'Keycloak을 실제로 멈추면 갱신이 503(행·쿠키 그대로), 다시 띄우면 다음 요청 200',
      down.status === 503 && downBody.code === 'KEYCLOAK_UNAVAILABLE' && rowDuring !== null && up.status === 200,
      `멈춤 ${down.status} ${downBody.code ?? ''} → 다시 띄운 뒤 ${up.status}`);
  } else {
    check('W-29', 'REFRESH-06', 'Keycloak 멈춰 보기', null, '--no-outage로 건너뜀');
  }

  // 위조한 at: 같은 이름·속성으로 서명만 망가뜨려 넣는다
  {
    const good = await cookie(ctx, 'demo', 'at');
    const broken = good.value.slice(0, -4) + (good.value.slice(-4) === 'AAAA' ? 'BBBB' : 'AAAA');
    const rowId = (await myRow(ctx, 'demo')).id;
    since = Date.now();
    await ctx.addCookies([{ name: good.name, value: broken, url: 'https://api.kss.test/', secure: true, httpOnly: true, sameSite: 'Lax', expires: good.expires }]);
    const tampered = await frontFetch(page, apiUrl('demo', '/api/me'));
    await sleep(300);
    const refreshCalls = await kcEvents(kcSid, since, 'REFRESH_TOKEN');
    const audit = await auditEnded('demo', 'invalid_token', rowId);
    check('W-30', 'REQ-04', '서명이 망가진 at: 401, 세션 행·쿠키 삭제, Keycloak 갱신 안 부름, 감사 로그 사유 invalid_token',
      tampered.status === 401 && !rowExists('demo', rowId) && (await cookiesOf(ctx, 'demo')).length === 0 && refreshCalls.length === 0 && audit !== false,
      `${tampered.status}, 감사 로그 ${shown(audit)}`);
  }

  // ============================================================ 7. 계정을 막으면
  section('7. Keycloak에서 계정을 막으면');
  {
    const user = { username: `walk-disabled-${Date.now()}`, password: 'walk-test-password' };
    const id = await createUser(user.username, user.password);
    tempUsers.push(id);
    const p = await (await newContext()).newPage();
    await loginFromFront(p, 'demo', user);
    const rowId = (await myRow(p.context(), 'demo'))?.id;
    await admin(`/users/${id}`, { method: 'PUT', body: { enabled: false } });
    await dropAt(p.context(), 'demo');
    const r = await frontFetch(p, apiUrl('demo', '/api/me'));
    const audit = await auditEnded('demo', 'refresh_failed', rowId);
    check('W-31', 'REFRESH-04', '관리자가 계정을 막으면 다음 갱신에서 Keycloak이 거절: 401, 행·쿠키 삭제, 사유 refresh_failed',
      rowId && r.status === 401 && !rowExists('demo', rowId) && (await cookiesOf(p.context(), 'demo')).length === 0 && audit !== false,
      `${r.status}, 감사 로그 ${shown(audit)}`);
    await p.context().close();
  }

  // ============================================================ 8. 앱 두 벌: SSO, 로그아웃, back-channel
  section('8. 앱 두 벌: SSO · 로그아웃 · back-channel 로그아웃');
  // W-30에서 demo 세션이 끝났으므로 다시 로그인한다. Keycloak SSO 세션은 살아 있어 폼이 안 나온다
  const demoAgainForm = await loginFromFront(page, 'demo', ALICE);
  const demo2Form = await loginFromFront(page, 'demo2', ALICE);
  const demoAt = jwtPayload((await cookie(ctx, 'demo', 'at')).value);
  const demo2At = jwtPayload((await cookie(ctx, 'demo2', 'at')).value);
  check('W-32', 'LOGIN-08', 'demo에 로그인한 브라우저는 demo2에 Keycloak 폼 없이 들어가고, 두 앱 토큰의 sid가 같다',
    !demoAgainForm && !demo2Form && demoAt.sid && demoAt.sid === demo2At.sid && (await myRow(ctx, 'demo2')) !== null,
    `폼 ${demo2Form ? '나옴' : '안 나옴'}, sid 같음 ${demoAt.sid === demo2At.sid}`);
  seenSids.add((await cookie(ctx, 'demo', 'sid')).value);
  seenSids.add((await cookie(ctx, 'demo2', 'sid')).value);
  const demo2RowId = (await myRow(ctx, 'demo2')).id;
  const demoRowId = (await myRow(ctx, 'demo')).id;
  const kcSidNow = demoAt.sid;

  await page.goto(`${APP}/`);
  await clickAndLand(page, '#demo-logout');
  check('W-33', 'LOGOUT-01', '화면의 로그아웃 버튼(폼 POST) → 화면 로그아웃 주소로 오고 demo 쿠키·행이 지워진다',
    page.url() === `${APP}/logged-out` && (await cookiesOf(ctx, 'demo')).length === 0 && !rowExists('demo', demoRowId)
      && (await auditEnded('demo', 'logout', demoRowId)) !== false, page.url());
  const kcGone = await waitFor(async () => !(await kcSessions(aliceId)).some((s) => s.id === kcSidNow));
  check('W-34', 'LOGOUT-01', 'Keycloak SSO 세션도 끝난다(관리 API)', kcGone, kcGone ? '끝남' : '남아 있음');
  const demo2RowGone = await waitFor(() => !rowExists('demo2', demo2RowId));
  const demo2Audit = await auditEnded('demo2', 'backchannel_logout', demo2RowId);
  check('W-35', 'BCL-01', 'Keycloak이 demo2에 back-channel 로그아웃을 보내 demo2 행이 지워진다(감사 로그 사유 backchannel_logout)',
    demo2RowGone && demo2Audit !== false, `행 ${demo2RowGone ? '지워짐' : '남음'}, 감사 로그 ${shown(demo2Audit)}`);
  const demo2StillValid = await frontFetch(page, apiUrl('demo2', '/api/me'));
  await dropAt(ctx, 'demo2');
  const since36 = Date.now();
  const demo2AfterExpiry = await frontFetch(page, apiUrl('demo2', '/api/me'));
  await sleep(500);
  // 행이 이미 없으므로 갱신하지 않고 401이어야 한다(Keycloak에 갱신을 부르면 back-channel이 안 된 것과 구별이 안 된다)
  const demo2Refresh = await kcRefreshEvents('demo2', since36);
  check('W-36', 'BCL-01', 'demo2는 at가 살아 있는 동안만 200(설계대로, 최대 60초), at가 끝나면 Keycloak 갱신 없이 401',
    demo2StillValid.status === 200 && demo2AfterExpiry.status === 401 && demo2Refresh.length === 0,
    `${demo2StillValid.status} → at 만료 뒤 ${demo2AfterExpiry.status}, demo2 갱신 이벤트 ${demo2Refresh.length}개`);
  const formAgain = await loginFromFront(page, 'demo', ALICE);
  check('W-37', 'LOGOUT-01', '로그아웃 뒤 다시 로그인하면 Keycloak 로그인 폼이 다시 나온다(SSO가 정말 끝남)', formAgain, formAgain ? '폼 나옴' : '폼 없이 들어감');
  // 다시 로그아웃하고, 쿠키 없는 상태에서 한 번 더
  await page.goto(`${APP}/`);
  await clickAndLand(page, '#demo-logout');
  await clickAndLand(page, '#demo-logout');
  check('W-38', 'LOGOUT-05', '이미 로그아웃된 상태에서 로그아웃 버튼 → 오류 없이 화면 로그아웃 주소', page.url() === `${APP}/logged-out`, page.url());

  // 서명만 빼면 맞는 logout_token(필요한 클레임을 모두 갖춤). 서명 말고 다른 이유로 거절되지 않게 한다
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const nowSec = Math.floor(Date.now() / 1000);
  const logoutClaims = { iss: `${KC}/realms/${REALM}`, aud: 'demo2', iat: nowSec, exp: nowSec + 60, jti: crypto.randomUUID(), sid: kcSidNow,
    events: { 'http://schemas.openid.net/event/backchannel-logout': {} } };
  const realmKid = json((await request(`${KC}/realms/${REALM}/protocol/openid-connect/certs`)).text).keys.find((k) => k.alg === 'RS256' && k.use === 'sig').kid;
  const signWith = (privateKey, header, claims) => {
    const input = `${b64(header)}.${b64(claims)}`;
    return `${input}.${crypto.sign('sha256', Buffer.from(input), privateKey).toString('base64url')}`;
  };
  const { privateKey: otherKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const badTokens = {
    '서명 없는 토큰(alg none, 클레임은 다 맞음)': `${b64({ alg: 'none', typ: 'logout+jwt' })}.${b64(logoutClaims)}.`,
    'realm 키 id로 다른 키가 서명한 토큰': signWith(otherKey, { alg: 'RS256', typ: 'logout+jwt', kid: realmKid }, { ...logoutClaims, jti: crypto.randomUUID() }),
    '모양이 깨진 토큰': 'not-a-jwt',
  };
  for (const [label, logoutToken] of Object.entries(badTokens)) {
    const r = await request(apiUrl('demo2', '/logout/connect/back-channel/keycloak'), {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form({ logout_token: logoutToken }),
    });
    check('W-39', 'BCL-02 · 04', `back-channel 주소에 ${label}: 400 (CSRF·Origin 없이 와도 403이 아니라 토큰 검사로 거절)`, r.status === 400, `${r.status}`);
  }

  // ============================================================ 9. 실제 시간 (--slow)
  if (SLOW) {
    section('9. 실제 시간을 기다리는 것 (같이 돌림)');
    const slowLogin = async (label) => {
      const user = { username: `walk-${label}-${Date.now()}`, password: 'walk-test-password' };
      const id = await createUser(user.username, user.password);
      tempUsers.push(id);
      const p = await (await newContext()).newPage();
      await loginFromFront(p, 'demo', user);
      return { p, id, rowId: (await myRow(p.context(), 'demo'))?.id };
    };
    const [expiry, idle, absolute] = await Promise.all([slowLogin('expiry'), slowLogin('idle'), slowLogin('absolute')]);
    const startedAt = Date.now();
    await Promise.all([
      // at가 실제로 만료(60초 + 검증 여유 30초)된 뒤: 브라우저가 at 쿠키를 버리고, 다음 요청이 갱신돼 200
      (async () => {
        await sleep((AT_SECONDS + 35) * 1000);
        const atGone = !(await cookie(expiry.p.context(), 'demo', 'at'));
        const r = await frontFetch(expiry.p, apiUrl('demo', '/api/me'));
        check('S-01', 'REFRESH-01 (실제 시간)', '95초 쉬면 브라우저가 at 쿠키를 버리고, 다음 요청은 갱신돼 200',
          atGone && r.status === 200 && Boolean(await cookie(expiry.p.context(), 'demo', 'at')), `at 쿠키 ${atGone ? '버려짐' : '남음'} → ${r.status}`);
      })(),
      // Client Session Idle(2분) 동안 요청이 없으면 Keycloak이 리프레시 토큰을 거절 → 401
      (async () => {
        await sleep((IDLE_SECONDS + 10) * 1000);
        const r = await frontFetch(idle.p, apiUrl('demo', '/api/me'));
        const audit = (await auditEnded('demo', 'idle', idle.rowId)) || (await auditEnded('demo', 'refresh_failed', idle.rowId));
        check('S-02', 'REFRESH-05 (실제 시간)', '2분 넘게 요청이 없으면 401, 행 삭제(사유 idle 또는 refresh_failed)',
          r.status === 401 && !rowExists('demo', idle.rowId) && audit !== false, `${r.status}, 감사 로그 ${shown(audit)}`);
      })(),
      // 절대 상한(3분): 계속 쓰고 있어도 끝난다. 브라우저는 sid 쿠키를 절대 상한에 맞춰 버린다
      (async () => {
        const savedSid = await cookie(absolute.p.context(), 'demo', 'sid');
        const statuses = [];
        while (Date.now() - startedAt < (ABSOLUTE_SECONDS + 10) * 1000) {
          statuses.push((await frontFetch(absolute.p, apiUrl('demo', '/api/me'))).status);
          await sleep(40_000);
        }
        const r = await frontFetch(absolute.p, apiUrl('demo', '/api/me'));
        const sidGone = !(await cookie(absolute.p.context(), 'demo', 'sid'));
        check('S-03', 'COOKIE-03 (실제 시간)', '40초마다 계속 써도 3분(절대 상한)이 지나면 401, 브라우저가 sid 쿠키를 절대 상한에 맞춰 버린다',
          statuses.every((s) => s === 200) && r.status === 401 && sidGone, `쓰는 동안 ${statuses.join(',')} → 3분 뒤 ${r.status}, sid 쿠키 ${sidGone ? '버려짐' : '남음'}`);
        // 버려진 sid 쿠키를 다시 넣어 서버의 절대 상한 검사를 거치게 한다: Keycloak을 부르지 않고 401, 행 삭제, 사유 absolute
        const rowStill = rowExists('demo', absolute.rowId);
        await absolute.p.context().addCookies([{ name: savedSid.name, value: savedSid.value, url: 'https://api.kss.test/', secure: true, httpOnly: true, sameSite: 'Lax', expires: Math.floor(Date.now() / 1000) + 600 }]);
        const sinceAbs = Date.now();
        const again = await frontFetch(absolute.p, apiUrl('demo', '/api/me'));
        await sleep(500);
        const audit = await auditEnded('demo', 'absolute', absolute.rowId);
        const refreshCalls = await kcRefreshEvents('demo', sinceAbs);
        check('S-04', 'REFRESH-03 (실제 시간)', '절대 상한이 지난 sid 쿠키를 다시 보내면 Keycloak을 부르지 않고 401, 행 삭제(사유 absolute)',
          rowStill ? again.status === 401 && !rowExists('demo', absolute.rowId) && audit !== false && refreshCalls.length === 0 : null,
          rowStill ? `${again.status}, 감사 로그 ${shown(audit)}, 갱신 이벤트 ${refreshCalls.length}개` : '정리 작업이 행을 먼저 지워 서버 검사 길을 못 봄');
      })(),
    ]);
    for (const s of [expiry, idle, absolute]) await s.p.context().close();
  }

  // ============================================================ 10. 로그
  section('10. 로그');
  for (const app of ['demo', 'demo2']) {
    if (!LOGS) {
      check('W-40', 'EVT-02', `${app} 로그에 토큰·sid 원문이 없다`, null, '--no-logs로 건너뜀');
      continue;
    }
    const log = appLog(app);
    const jwtLike = (log.match(/eyJ[A-Za-z0-9_-]{10,}/g) ?? []).length;
    const rawSid = [...seenSids].filter((s) => log.includes(s)).length;
    check('W-40', 'EVT-02', `${app} 로그에 JWT 모양(eyJ…)과 이번 실행의 sid 쿠키 원문(${seenSids.size}개)이 없다`, jwtLike === 0 && rawSid === 0 && seenSids.size > 0,
      `JWT 모양 ${jwtLike}개, sid 원문 ${rawSid}개`);
  }
} catch (e) {
  exitCode = 2;
  abortedBy = String(e?.message ?? e).split('\n')[0];
  console.error('\n중간에 멈춤:', e);
} finally {
  if (keycloakStopped) { try { startKeycloak(); } catch { console.error('Keycloak을 다시 띄우지 못했습니다: integration-tests/local-stack.sh up'); } }
  for (const id of tempUsers) {
    try { await admin(`/users/${id}`, { method: 'DELETE' }); } catch { /* 지우기 실패는 넘긴다 */ }
  }
  const version = browser.version();
  await browser.close();
  const checks = results.filter((r) => !r.section);
  const count = (state) => checks.filter((r) => r.state === state).length;
  const [passed, failed, skipped] = [count('pass'), count('fail'), count('skip')];
  const summary = `${passed}/${passed + failed} 통과${skipped ? `, ${skipped}개 건너뜀` : ''}${abortedBy ? ` — 중간에 멈춤(${abortedBy}), 뒤 확인은 돌지 않음` : ''}`;
  console.log(`\n${summary} (Chromium ${version})`);
  if (process.env.KSS_REPORT) {
    const lines = [`# 기능별 손 확인 결과`, '', `- 실행: ${new Date().toISOString()}, Chromium ${version}, ${SLOW ? '실제 시간 포함' : '실제 시간 제외'}`, `- 결과: ${summary}`, ''];
    const KO = { pass: '통과', fail: '실패', skip: '건너뜀' };
    for (const r of results) {
      if (r.section) { lines.push('', `## ${r.section}`, '', '| # | 시나리오 | 확인 | 결과 | 값 |', '|---|---|---|---|---|'); continue; }
      lines.push(`| ${r.id} | ${r.scenario} | ${r.name} | ${KO[r.state]} | ${r.detail.replaceAll('|', '\\|')} |`);
    }
    fs.writeFileSync(process.env.KSS_REPORT, lines.join('\n') + '\n');
  }
  process.exit(exitCode || (failed ? 1 : 0));
}
