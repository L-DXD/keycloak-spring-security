// 눈으로 보는 데모: 브라우저 창 하나를 띄워 기능을 하나씩 천천히 보여 준다 (docs/v3/03-검증-환경.md 4-3절).
// 창 오른쪽 아래 안내판에 지금 보는 기능과 결과가 뜨고, 안내판의 "다음"을 누르면 다음 기능으로 넘어간다.
// feature-walkthrough.mjs가 확인을 빠짐없이 자동으로 센다면, 이 스크립트는 사람이 화면을 보며 따라가게 한다.
// Gradle 빌드에 묶지 않는다.
//
// 준비 (저장소 루트에서, feature-walkthrough.mjs와 같다):
//   integration-tests/local-stack.sh up
//   ./gradlew :integration-tests:servlet-app:bootRun > integration-tests/servlet-app/build/demo.log                                        # 다른 창
//   ./gradlew :integration-tests:servlet-app:bootRun --args=--spring.profiles.active=demo2 > integration-tests/servlet-app/build/demo2.log  # 다른 창
// 실행:
//   node integration-tests/browser/demo-tour.mjs [--chrome] [--auto[=밀리초]] [--headless] [--no-outage]
//     --chrome     이 PC에 깔린 Google Chrome으로 띄운다(Playwright 브라우저를 따로 받지 않아도 된다). 없으면 Playwright Chromium
//     --auto       "다음"을 기다리지 않고 정한 시간(기본 4초)마다 넘어간다
//     --headless   창 없이 돈다(스크립트 확인용). --auto와 같이 쓴다
//     --no-outage  Keycloak 컨테이너를 잠깐 멈춰 보는 단계를 건너뛴다
//   KSS_DEMO_LOG·KSS_DEMO2_LOG에 bootRun 출력 파일을 주면 감사 로그 줄도 보여 준다(안 주면 그 줄만 뺀다).
//   KSS_TOUR_SHOTS=<폴더>를 주면 단계마다 화면을 PNG로 남긴다.
//   KSS_TOUR_NOTES=<JSON 파일>을 주면 단계마다 덧붙일 글(예: 팀 점검표 번호)을 안내판에 같이 띄우고, 맨 끝에 요약 단계를 더한다.
//     모양: {"label": "덧붙임 제목", "steps": {"<단계 키>": ["글", ...]}, "summary": {"title": "...", "look": "...", "lines": ["..."]}}
//     단계 키는 아래 step('키', ...)의 첫 인자다. 없는 키를 적으면 시작할 때 알려 준다.
//
// 브라우저는 따로 만든 빈 프로필로 뜬다(평소 쓰는 크롬 프로필·쿠키를 건드리지 않는다). *.kss.test는 이 브라우저 안에서만 이 PC로 푼다
// (/etc/hosts를 고치지 않는다). 테스트 CA는 이 브라우저에서만 인증서 오류를 넘긴다.
// 모든 주소가 이 PC 안이다. HTTPS_PROXY 같은 프록시 환경 변수가 있으면 지우고 돌린다(브라우저가 그 프록시로 보낸다).
// 값은 모두 테스트 값이다(realm-kss-demo.json, compose.yaml). 공용 사용자 alice로 로그인·로그아웃만 한다.
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import crypto from 'node:crypto';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const COMPOSE = path.join(ROOT, 'compose.yaml');
const TLS_DIR = process.env.KSS_TLS_DIR ?? path.join(ROOT, 'servlet-app/build/e2e/tls');
const ARGS = process.argv.slice(2);
const AUTO_ARG = ARGS.find((a) => a === '--auto' || a.startsWith('--auto='));
const AUTO_MS = AUTO_ARG ? Number(AUTO_ARG.split('=')[1] ?? 4000) : null;
const HEADLESS = ARGS.includes('--headless');
const CHROME = ARGS.includes('--chrome');
const OUTAGE = !ARGS.includes('--no-outage');
const SHOTS = process.env.KSS_TOUR_SHOTS;
const NOTES = process.env.KSS_TOUR_NOTES ? JSON.parse(fs.readFileSync(process.env.KSS_TOUR_NOTES, 'utf8')) : null;
if (HEADLESS && AUTO_MS === null) {
  console.error('--headless는 --auto와 같이 씁니다("다음"을 누를 사람이 없습니다)');
  process.exit(2);
}

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
const REUSE_WINDOW_MS = 11_000; // session.refresh-reuse-window(기본 10초) + 여유. 이 안의 갱신은 앞 결과를 다시 쓴다
const TYPE_DELAY = HEADLESS ? 0 : 70;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const json = (t) => { try { return JSON.parse(t); } catch { return null; } };
async function waitFor(fn, { timeoutMs = 10_000, everyMs = 250 } = {}) {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const v = await fn();
    if (v || Date.now() > end) return v;
    await sleep(everyMs);
  }
}

// ---------------------------------------------------------------- Node 쪽 HTTP (*.kss.test를 이 PC로), Keycloak 관리 API

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
// 테스트 관리자 admin/admin (compose.yaml)
async function admin(pathAndQuery) {
  const token = json((await request(`${KC}/realms/master/protocol/openid-connect/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli', username: 'admin', password: 'admin' }).toString(),
  })).text).access_token;
  return json((await request(`${KC}/admin/realms/${REALM}${pathAndQuery}`, { headers: { Authorization: `Bearer ${token}` } })).text);
}
const userId = async (username) => (await admin(`/users?username=${encodeURIComponent(username)}&exact=true`))[0].id;
const kcSessions = async (id) => (await admin(`/users/${id}/sessions`)) ?? [];
// 이 Keycloak 세션(kc_sid)에서 since(ms) 뒤에 생긴 사용자 이벤트
async function kcEvents(kcSid, since, type) {
  const day = new Date(since).toISOString().slice(0, 10);
  const events = (await admin(`/events?max=1000&dateFrom=${day}${type ? `&type=${type}` : ''}`)) ?? [];
  return events.filter((e) => e.sessionId === kcSid && e.time >= since);
}
async function kcRefreshEvents(clientId, since) {
  const day = new Date(since).toISOString().slice(0, 10);
  const events = (await admin(`/events?max=1000&client=${clientId}&dateFrom=${day}`)) ?? [];
  return events.filter((e) => e.time >= since && e.type.startsWith('REFRESH_TOKEN'));
}

// ---------------------------------------------------------------- DB (compose의 postgres 컨테이너에 psql), 감사 로그

function sql(query) {
  return execFileSync('docker', ['compose', '-f', COMPOSE, 'exec', '-T', 'postgres', 'psql', '-U', 'kss', '-d', 'kss', '-tA', '-F', '|', '-c', query],
    { encoding: 'utf8' }).trim();
}
const sidHash = (sid) => crypto.createHash('sha256').update(sid, 'ascii').digest('hex');
function rowWhere(app, where) {
  const out = sql(`select id, sid_hash, kc_sid, encode(refresh_token_enc, 'escape') like 'eyJ%', refreshed_at
                   from ${APPS[app].schema}.auth_session where ${where}`);
  if (!out) return null;
  const [id, sidHashValue, kcSid, plain, refreshedAt] = out.split('\n')[0].split('|');
  return { id, sidHash: sidHashValue, kcSid, plain: plain === 't', refreshedAt };
}
const rowExists = (app, id) => rowWhere(app, `id = '${id}'`) !== null;
async function myRow(context, app) {
  const sid = await cookie(context, app, 'sid');
  return sid ? rowWhere(app, `sid_hash = '${sidHash(sid.value)}'`) : null;
}
// 감사 로그 한 줄을 기다린다. 로그 파일을 안 줬으면 null(그 줄은 안내판에 안 띄운다)
async function auditLine(app, text) {
  const file = APPS[app].log;
  if (!file || !fs.existsSync(file)) return null;
  return waitFor(() => fs.readFileSync(file, 'utf8').split('\n').some((l) => l.includes(text)), { timeoutMs: 5_000 });
}

let keycloakStopped = false;
function stopKeycloak() {
  keycloakStopped = true;
  execFileSync('docker', ['compose', '-f', COMPOSE, 'stop', 'keycloak'], { stdio: 'ignore' });
}
function startKeycloak() {
  execFileSync('docker', ['compose', '-f', COMPOSE, 'up', '-d', '--wait', '--no-recreate', 'keycloak'], { stdio: 'ignore' });
  keycloakStopped = false;
}

// ---------------------------------------------------------------- 브라우저

const browser = await chromium.launch({
  headless: HEADLESS,
  channel: CHROME ? 'chrome' : undefined,
  slowMo: HEADLESS ? 0 : 120,
  // 주소(origin)는 그대로 두고 연결만 이 PC로 보낸다
  args: ['--host-resolver-rules=MAP *.kss.test 127.0.0.1, MAP evil.test 127.0.0.1', '--window-size=1440,960'],
});
const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: HEADLESS ? { width: 1440, height: 900 } : null, locale: 'ko-KR' });
// 이번 실행에서 앱이 내린 sid 쿠키 값 전부(마지막 단계: 로그에 원문이 없어야 한다). 302 응답의 Set-Cookie도 본다
const seenSids = new Set();
ctx.on('response', async (response) => {
  try {
    for (const h of await response.headersArray()) {
      const m = h.name.toLowerCase() === 'set-cookie' && /^__Host-[A-Za-z0-9-]+_sid=([^;]+)/.exec(h.value);
      if (m && m[1]) seenSids.add(m[1]);
    }
  } catch { /* 페이지가 닫히며 끊긴 응답은 넘긴다 */ }
});
const apiUrl = (app, p) => `${APPS[app].api}${p}`;
async function cookiesOf(context, app) {
  return (await context.cookies('https://api.kss.test')).filter((c) => c.name.startsWith(`__Host-${app}_`));
}
const cookie = async (context, app, kind) => (await cookiesOf(context, app)).find((c) => c.name === `__Host-${app}_${kind}`);
const dropAt = (context, app) => context.clearCookies({ name: `__Host-${app}_at` });
const jwtPayload = (t) => JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString('utf8'));

// ---------------------------------------------------------------- 안내판

// 지금 안내판에 띄운 내용. 화면이 바뀌면(load) 새 페이지에 다시 그린다
let board = null;
let nextResolve = null;
await ctx.exposeBinding('kssTourNext', () => { const r = nextResolve; nextResolve = null; r?.(); });

// 브라우저 안에서 돈다. 페이지 CSS와 섞이지 않게 shadow DOM에 그리고, 응답 글은 textContent로만 넣는다
function drawBoard(s) {
  let host = document.getElementById('kss-tour');
  if (!host) {
    host = document.createElement('div');
    host.id = 'kss-tour';
    (document.body ?? document.documentElement).appendChild(host);
    const root = host.attachShadow({ mode: 'open' });
    const style = document.createElement('style');
    style.textContent = `
      .box { position: fixed; right: 16px; bottom: 16px; width: 470px; max-height: 70vh; overflow: auto; z-index: 2147483647;
        background: #fff; color: #111; border: 2px solid #1f6feb; border-radius: 10px; box-shadow: 0 8px 28px rgba(0,0,0,.25);
        font: 14px/1.5 system-ui, -apple-system, "Apple SD Gothic Neo", sans-serif; }
      .head { display: flex; justify-content: space-between; align-items: center; background: #1f6feb; color: #fff; padding: 6px 12px; font-size: 12px; }
      .head button { all: unset; cursor: pointer; padding: 0 4px; }
      .body { padding: 10px 14px 12px; }
      h2 { margin: 0 0 6px; font-size: 17px; }
      .look { margin: 0 0 8px; color: #333; }
      ul { margin: 0; padding: 0; list-style: none; }
      li { padding: 3px 0 3px 24px; position: relative; border-top: 1px solid #eee; word-break: break-all; }
      li::before { position: absolute; left: 2px; top: 3px; }
      li.pass::before { content: "✅"; } li.fail::before { content: "❌"; } li.info::before { content: "•"; left: 8px; }
      li.fail { color: #b00020; font-weight: 600; }
      .foot { display: flex; justify-content: space-between; align-items: center; margin-top: 10px; }
      .state { color: #666; font-size: 12px; }
      .next { font: inherit; font-weight: 700; padding: 6px 16px; border: 0; border-radius: 6px; background: #1f6feb; color: #fff; cursor: pointer; }
      .next[disabled] { background: #9db7e0; cursor: default; }
      .notes { margin: 0 0 8px; padding: 6px 10px; background: #f3f6fb; border-left: 3px solid #1f6feb; border-radius: 4px; font-size: 13px; }
      .notes b { display: block; font-size: 12px; color: #1f6feb; }
      .notes div { padding: 1px 0; }
      .min .body { display: none; } .min { width: 220px; }`;
    root.appendChild(style);
    const box = document.createElement('div');
    box.className = 'box';
    root.appendChild(box);
  }
  const root = host.shadowRoot;
  const box = root.querySelector('.box');
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };
  box.replaceChildren();
  const head = el('div', 'head');
  head.append(el('span', '', `kss 데모 · ${s.n} / ${s.total}`));
  const fold = el('button', '', box.classList.contains('min') ? '펴기' : '접기');
  fold.addEventListener('click', () => { box.classList.toggle('min'); fold.textContent = box.classList.contains('min') ? '펴기' : '접기'; });
  head.append(fold);
  const body = el('div', 'body');
  body.append(el('h2', '', s.title), el('p', 'look', s.look));
  if (s.notes && s.notes.length) {
    const notes = el('div', 'notes');
    notes.append(el('b', '', s.notesLabel || '덧붙임'));
    for (const line of s.notes) notes.append(el('div', '', line));
    body.append(notes);
  }
  const list = el('ul');
  for (const r of s.results) list.append(el('li', r.ok === null ? 'info' : r.ok ? 'pass' : 'fail', r.text));
  body.append(list);
  const foot = el('div', 'foot');
  const stateText = { running: '보여 주는 중…', waiting: s.auto ? '잠시 뒤 저절로 넘어가요' : '다 봤으면 "다음"을 누르세요', done: '끝났어요' }[s.state];
  foot.append(el('span', 'state', stateText));
  const next = el('button', 'next', s.state === 'done' ? '닫기' : '다음 ▶');
  next.disabled = s.state === 'running';
  next.addEventListener('click', () => { next.disabled = true; window.kssTourNext(); });
  foot.append(next);
  body.append(foot);
  box.append(head, body);
}
async function render(page) {
  if (!board) return;
  try { await page.evaluate(drawBoard, board); } catch { /* 화면 이동 중이면 다음 load에서 다시 그린다 */ }
}
async function waitNext(page) {
  if (AUTO_MS !== null) {
    await sleep(AUTO_MS);
    return;
  }
  await new Promise((resolve) => { nextResolve = resolve; });
  await render(page);
}

// 누를 곳을 잠깐 표시하고 누른다
async function point(page, selector) {
  await page.locator(selector).scrollIntoViewIfNeeded();
  await page.evaluate((sel) => {
    document.querySelectorAll('[data-kss-point]').forEach((e) => { e.style.outline = ''; e.removeAttribute('data-kss-point'); });
    const e = document.querySelector(sel);
    if (e) { e.setAttribute('data-kss-point', ''); e.style.outline = '3px solid #f59e0b'; e.style.outlineOffset = '2px'; }
  }, selector);
  if (!HEADLESS) await sleep(800);
}

// 화면(app.kss.test)의 버튼을 누르고, 버튼이 결과 칸에 쓴 "GET /api/me: 401\n{...}"를 읽는다
async function press(page, app, button) {
  const out = `#${app}-out`;
  await page.evaluate((s) => { document.querySelector(s).textContent = '…'; }, out);
  await point(page, `#${app}-${button}`);
  await page.click(`#${app}-${button}`);
  await page.waitForFunction((s) => { const t = document.querySelector(s).textContent; return t && t !== '…'; }, out);
  const text = await page.textContent(out);
  const m = /^[^\n]*?: (\d+)\n([\s\S]*)$/.exec(text);
  return { status: m ? Number(m[1]) : 0, text: m ? m[2] : text };
}
// 화면 페이지 안에서 fetch (credentials 포함). 결과를 화면 결과 칸에도 쓴다(있으면)
async function frontFetch(page, url, init = {}, { app, label } = {}) {
  const r = await page.evaluate(async ({ url, init }) => {
    try {
      const res = await fetch(url, { credentials: 'include', ...init });
      return { status: res.status, text: await res.text() };
    } catch (e) {
      return { status: 0, error: `${e.name}: ${e.message}` };
    }
  }, { url, init });
  if (app && label) {
    await page.evaluate(({ sel, line }) => { const e = document.querySelector(sel); if (e) e.textContent = line; },
      { sel: `#${app}-out`, line: `${label}: ${r.status || '요청 실패'}\n${r.text ?? r.error}` });
  }
  return r;
}
const csrfToken = async (page, app) => json((await frontFetch(page, apiUrl(app, '/api/csrf'))).text)?.token;

// 누르고 화면 이동이 끝날 때까지 기다린다(302는 건너뛰고 실제로 열린 페이지 하나)
async function clickAndLand(page, selector) {
  await point(page, selector);
  await Promise.all([page.waitForEvent('framenavigated', (f) => f === page.mainFrame()), page.click(selector)]);
  await page.waitForLoadState('load');
}
// 이 페이지에서 HTML 폼을 만들어 POST한다(최상위 이동). 응답 상태·본문·보낸 쿠키를 돌려준다
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
  const text = await response.text();
  return { status: response.status(), body: json(text) ?? {}, text, cookie: (await response.request().allHeaders())['cookie'] ?? '' };
}
// 화면의 로그인 버튼을 누른다. Keycloak 로그인 폼이 나왔는지 돌려준다(폼이 나오면 그 화면에서 멈춘다)
async function pressLogin(page, app) {
  // 302는 화면에 남지 않으므로 처음 열리는 페이지가 Keycloak 로그인 폼이거나(로그인 필요) 화면이다(SSO)
  await clickAndLand(page, `#${app}-login`);
  if (new URL(page.url()).origin !== KC) return false;
  await page.waitForSelector('#kc-form-login');
  return true;
}
async function fillLogin(page, user) {
  await point(page, '#username');
  await page.fill('#username', '');
  await page.type('#username', user.username, { delay: TYPE_DELAY });
  await page.type('#password', user.password, { delay: TYPE_DELAY });
  await point(page, '#kc-login');
  await Promise.all([page.waitForURL((u) => u.origin === APP), page.click('#kc-login')]);
  await page.waitForLoadState('load');
}
// 같은 세션의 앞 갱신에서 재사용 시간이 지날 때까지 기다린다(갱신 횟수를 세거나 Keycloak을 멈춰 볼 때)
async function pastReuseWindow(note, since) {
  const left = since + REUSE_WINDOW_MS - Date.now();
  if (left > 0) {
    await note(null, `앞 갱신 결과를 다시 쓰는 시간(10초)이 지나기를 ${Math.ceil(left / 1000)}초 기다려요`);
    await sleep(left);
  }
}

// ---------------------------------------------------------------- 단계

const page = await ctx.newPage();
page.on('load', () => render(page));
const steps = [];
const step = (key, title, look, run) => steps.push({ key, title, look, run });
const st = {}; // 단계끼리 넘기는 값
const aliceId = await userId(ALICE.username);
const shortName = (c) => c.name.replace(/^__Host-[a-z0-9]+_/, '');
const code = (r) => json(r.text)?.code ?? '';
// Node에서 브라우저 쿠키를 그대로 붙여 API를 부른다(브라우저가 못 바꾸는 Origin 헤더를 정해 보낼 때)
async function asBrowser(app, p, { method = 'GET', origin, headers = {}, body } = {}) {
  const jar = (await cookiesOf(ctx, app)).map((c) => `${c.name}=${c.value}`).join('; ');
  return request(apiUrl(app, p), { method, body, headers: { Cookie: jar, ...(origin ? { Origin: origin } : {}), ...headers } });
}

step('start', '화면 열기',
  '화면 주소(app.kss.test)와 API 주소(api.kss.test:8443은 demo, :8444는 demo2)가 달라요. 둘은 같은 사이트(kss.test)예요. 로그인 쿠키는 API 주소에만 생겨요. '
  + '로그인 뒤 돌아와야 할 곳을 보려고 /items/3 화면에서 시작해요.',
  async (note) => {
    await page.goto(`${APP}/items/3`);
    await note(null, `지금 화면 ${page.url()}`);
    const c = await cookiesOf(ctx, 'demo');
    await note(c.length === 0, `demo 쿠키 ${c.length}개 (로그인 전이라 없어요)`);
  });

step('before-login', '로그인 전에는',
  '허용 목록(permit-all-paths)에 넣은 주소만 그냥 되고, 나머지는 모두 로그인이 필요해요. 로그인이 필요한 주소는 401과 "로그인 주소"를 JSON으로 돌려줘요.',
  async (note) => {
    const ping = await frontFetch(page, apiUrl('demo', '/api/public/ping'));
    await note(ping.status === 200, `GET /api/public/ping (허용 주소) → ${ping.status}`);
    const unknown = await frontFetch(page, apiUrl('demo', '/api/anything-else'));
    await note(unknown.status === 401, `GET /api/anything-else (목록에 없는 주소) → ${unknown.status} ${code(unknown)}`);
    const me = await press(page, 'demo', 'me');
    const body = json(me.text) ?? {};
    await note(me.status === 401 && body.code === 'AUTHENTICATION_REQUIRED', `"내 정보" GET /api/me → ${me.status} ${body.code ?? ''}`);
    await note(body.loginUrl === '/oauth2/authorization/keycloak', `응답의 로그인 주소 loginUrl = ${body.loginUrl}`);
  });

step('login-button', '로그인 버튼 → Keycloak 로그인 화면',
  '화면의 "로그인"은 API의 /oauth2/authorization/keycloak?return=/items/3 으로 가요. 앱이 Keycloak으로 보낸 요청에 PKCE(S256)·state·nonce가 붙었는지, scope가 openid뿐인지(offline_access 없음) 봐요.',
  async (note) => {
    const authorize = page.waitForRequest((r) => r.url().startsWith(`${KC}/realms/${REALM}/protocol/openid-connect/auth`));
    const formShown = await pressLogin(page, 'demo');
    const q = Object.fromEntries(new URL((await authorize).url()).searchParams);
    await note(formShown, `Keycloak 로그인 화면 (${new URL(page.url()).host})`);
    await note(q.code_challenge_method === 'S256' && Boolean(q.code_challenge), `PKCE code_challenge_method=${q.code_challenge_method}`);
    await note(Boolean(q.state && q.nonce), `state·nonce ${q.state && q.nonce ? '있음' : '없음'}`);
    await note((q.scope ?? '').split(' ').includes('openid') && !(q.scope ?? '').includes('offline_access'), `client_id=${q.client_id}, scope=${q.scope}`);
  });

step('login-form', '아이디·비밀번호 넣기 → 원래 화면으로',
  '테스트 사용자 alice로 로그인해요. Keycloak이 앱으로 돌려보내면 앱이 토큰을 받고, 처음 있던 /items/3 화면으로 돌아와야 해요.',
  async (note) => {
    await fillLogin(page, ALICE);
    await note(page.url() === `${APP}/items/3`, `돌아온 화면 ${page.url()}`);
  });

step('cookies', '쿠키 3개 · 토큰 · DB 행',
  '브라우저에는 sid·at·csrf 쿠키 셋만 생겨요. 모두 __Host- 이름, Secure·HttpOnly·SameSite=Lax·Path=/, Domain 없이 api.kss.test 전용이에요. '
  + 'ID 토큰은 어디에도 두지 않고, 리프레시 토큰은 쿠키가 아니라 앱 DB 행에 암호문으로만 있어요.',
  async (note) => {
    const cs = await cookiesOf(ctx, 'demo');
    const names = cs.map(shortName).sort();
    await note(JSON.stringify(names) === '["at","csrf","sid"]', `쿠키 ${cs.map((c) => c.name).sort().join(', ')}`);
    const now = Date.now() / 1000;
    for (const c of cs.sort((a, b) => a.name.localeCompare(b.name))) {
      await note(c.secure && c.httpOnly && c.sameSite === 'Lax' && c.path === '/' && c.domain === 'api.kss.test',
        `${shortName(c)}: Secure ${c.secure ? 'O' : 'X'} · HttpOnly ${c.httpOnly ? 'O' : 'X'} · SameSite=${c.sameSite} · Path=${c.path} · ${c.domain} 전용 · ${Math.round(c.expires - now)}초 뒤 만료`);
    }
    const others = (await ctx.cookies('https://api.kss.test')).filter((c) => /JSESSIONID|id_token|access_token|refresh/i.test(c.name));
    await note(others.length === 0, `JSESSIONID·ID 토큰·리프레시 토큰 쿠키 ${others.length ? '있음' : '없음'}`);
    const at = jwtPayload((await cookie(ctx, 'demo', 'at')).value);
    const aud = [].concat(at.aud ?? []);
    await note(at.iss === `${KC}/realms/${REALM}` && aud.includes('demo') && at.azp === 'demo' && at.typ === 'Bearer',
      `at 토큰: iss=${at.iss}, aud에 demo ${aud.includes('demo') ? '있음' : '없음'}, azp=${at.azp}, typ=${at.typ}`);
    await note(Boolean(at.sid), `at 토큰에 Keycloak 세션 sid ${at.sid ? '있음' : '없음'}`);
    const visible = await page.evaluate(() => ({ cookie: document.cookie, local: localStorage.length, session: sessionStorage.length }));
    await note(!visible.cookie.includes('__Host-') && visible.local === 0 && visible.session === 0,
      `화면 스크립트: document.cookie = ${JSON.stringify(visible.cookie)}, localStorage ${visible.local}개, sessionStorage ${visible.session}개`);
    const row = await myRow(ctx, 'demo');
    await note(Boolean(row && !row.plain && /^[0-9a-f]{64}$/.test(row.sidHash) && row.sidHash !== (await cookie(ctx, 'demo', 'sid')).value),
      row ? `DB 세션 행(앱 DB): sid는 해시(${row.sidHash.slice(0, 12)}…, 64자)로만, 리프레시 토큰은 암호문(eyJ로 시작 안 함)` : 'DB 세션 행 없음');
    const columns = sql(`select string_agg(column_name, ',' order by ordinal_position) from information_schema.columns where table_schema = 'public' and table_name = 'auth_session'`);
    await note(!/id_token|access_token/.test(columns), `세션 행 칸: ${columns}`);
    const audit = await auditLine('demo', `[KSS] 세션 만듦 session=${row?.id}`);
    if (audit !== null) await note(audit, `감사 로그 "[KSS] 세션 만듦" ${audit ? '있음' : '없음'}`);
  });

step('me', '내 정보 (로그인한 뒤)',
  '화면이 credentials: include로 API를 부르면 쿠키가 같이 가요. 앱은 at 쿠키의 토큰을 스스로 검사하고 누구인지 알려 줘요.',
  async (note) => {
    const me = await press(page, 'demo', 'me');
    const body = json(me.text) ?? {};
    await note(me.status === 200 && body.username === 'alice', `"내 정보" GET /api/me → ${me.status}, username=${body.username}`);
  });

step('item', '항목 만들기 (CSRF 토큰을 헤더로)',
  '상태를 바꾸는 요청(POST)은 CSRF 토큰이 있어야 해요. 화면이 GET /api/csrf로 토큰을 받아 X-XSRF-TOKEN 헤더로 보내요.',
  async (note) => {
    const r = await press(page, 'demo', 'item');
    const body = json(r.text) ?? {};
    await note(r.status === 201 && body.createdBy === aliceId, `"항목 만들기" POST /api/items → ${r.status}, createdBy=alice의 sub`);
  });

step('no-csrf', 'CSRF 토큰이 없으면 막힘',
  '같은 요청을 토큰 없이 보내면 403이에요. 로그아웃(POST /logout)도 토큰 없이는 안 되고 세션이 그대로 남아요.',
  async (note) => {
    const r = await frontFetch(page, apiUrl('demo', '/api/items'), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"name":"토큰 없음"}' },
      { app: 'demo', label: 'POST /api/items (CSRF 토큰 없음)' });
    await note(r.status === 403 && code(r) === 'INVALID_CSRF_TOKEN', `POST /api/items (토큰 없음) → ${r.status} ${code(r)}`);
    const out = await frontFetch(page, apiUrl('demo', '/logout'), { method: 'POST' });
    await note(out.status === 403 && (await myRow(ctx, 'demo')) !== null, `POST /logout (토큰 없음) → ${out.status}, 세션 그대로`);
  });

step('get-logout', '주소창으로 /logout 열기 (GET)',
  '링크나 주소창(GET)으로는 로그아웃되지 않아요. 405와 Allow: POST가 오고 세션은 그대로예요. 지금 창에 보이는 JSON이 그 응답이에요.',
  async (note) => {
    st.leaked = await csrfToken(page, 'demo'); // 다음 단계에서 "토큰이 새 나갔다"고 치고 쓴다
    const [res] = await Promise.all([page.waitForResponse((r) => r.url() === apiUrl('demo', '/logout')), page.goto(apiUrl('demo', '/logout'))]);
    const allow = (await res.allHeaders())['allow'];
    await note(res.status() === 405 && allow === 'POST', `GET /logout → ${res.status()}, Allow: ${allow}`);
    await note((await myRow(ctx, 'demo')) !== null, '세션 그대로 (로그아웃 안 됨)');
  });

step('same-site', '같은 사이트의 다른 화면 (evil.kss.test)',
  'evil.kss.test는 app.kss.test와 같은 사이트라 SameSite=Lax 쿠키가 따라가요. 그래도 앱이 요청의 Origin(허용한 화면은 app.kss.test 하나)을 보고 막아요. '
  + '토큰이 새 나갔다고 치고 넣어 봐도 403이에요. 이 화면의 fetch도 CORS로 막혀요.',
  async (note) => {
    await page.goto(`${SAME_SITE_OTHER}/`);
    await note(null, `지금 화면 ${page.url()}`);
    const f = await frontFetch(page, apiUrl('demo', '/api/me'));
    await note(f.status === 0, `여기서 fetch GET /api/me → ${f.status === 0 ? 'CORS로 막힘' : f.status}`);
    if (!HEADLESS) await sleep(1500);
    const r = await submitForm(page, apiUrl('demo', '/api/items'), { _csrf: st.leaked, name: 'same-site' });
    await note(r.status === 403 && r.cookie.includes('__Host-demo_sid'),
      `여기서 폼 POST /api/items (쿠키 감, 맞는 토큰까지 넣음) → ${r.status} ${r.body.code ?? r.text}`);
    // 브라우저 밖에서 쿠키·토큰을 그대로 붙이고 Origin만 바꿔 본다(브라우저는 Origin을 바꿀 수 없다)
    const headers = { 'Content-Type': 'application/json', 'X-XSRF-TOKEN': st.leaked };
    const evil = await asBrowser('demo', '/api/items', { method: 'POST', origin: 'https://evil.example', headers, body: '{}' });
    await note(evil.status === 403, `쿠키·토큰 맞고 Origin: https://evil.example → ${evil.status} ${json(evil.text)?.code ?? evil.text}`);
    const none = await asBrowser('demo', '/api/items', { method: 'POST', headers, body: '{}' });
    await note(none.status === 403 && json(none.text)?.code === 'ORIGIN_NOT_ALLOWED', `쿠키·토큰 맞고 Origin·Referer 없음 → ${none.status} ${json(none.text)?.code ?? none.text}`);
    const good = await asBrowser('demo', '/api/items', { method: 'POST', origin: APP, headers, body: '{}' });
    await note(good.status === 201, `같은 쿠키·토큰에 Origin: ${APP} → ${good.status}`);
  });

step('cross-site', '다른 사이트 (evil.test)',
  '완전히 다른 사이트에서는 SameSite=Lax라 폼 POST에 쿠키가 아예 안 가요. fetch도 CORS로 막혀요.',
  async (note) => {
    await page.goto(`${CROSS_SITE}/`);
    await note(null, `지금 화면 ${page.url()}`);
    const f = await frontFetch(page, apiUrl('demo', '/api/me'));
    await note(f.status === 0, `여기서 fetch GET /api/me → ${f.status === 0 ? 'CORS로 막힘' : f.status}`);
    if (!HEADLESS) await sleep(1500);
    const r = await submitForm(page, apiUrl('demo', '/api/items'), { name: 'cross-site' });
    await note(r.status === 403 && !r.cookie.includes('__Host-'), `여기서 폼 POST /api/items → ${r.status} ${r.body.code ?? r.text}, 쿠키 ${r.cookie.includes('__Host-') ? '감' : '안 감'}`);
  });

step('preflight', 'CORS 사전 확인 (OPTIONS)',
  '브라우저가 POST 전에 묻는 사전 확인에, 앱은 화면 주소(app.kss.test) 하나에만 "허용, 쿠키 포함, 헤더 Content-Type·X-XSRF-TOKEN·X-Background"를 답해요. 다른 주소에는 허용 헤더를 안 줘요.',
  async (note) => {
    const ask = (origin) => request(apiUrl('demo', '/api/items'), { method: 'OPTIONS', headers: {
      Origin: origin, 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type,x-xsrf-token,x-background' } });
    const goodPre = await ask(APP);
    const h = goodPre.headers;
    await note(h['access-control-allow-origin'] === APP && h['access-control-allow-credentials'] === 'true',
      `Origin ${APP} → ${goodPre.status}, Allow-Origin=${h['access-control-allow-origin']}, Allow-Credentials=${h['access-control-allow-credentials']}`);
    await note(/x-xsrf-token/i.test(h['access-control-allow-headers'] ?? '') && /x-background/i.test(h['access-control-allow-headers'] ?? ''),
      `Allow-Headers=${h['access-control-allow-headers']}`);
    await note(null, `Allow-Methods=${h['access-control-allow-methods']}`);
    for (const other of [SAME_SITE_OTHER, 'https://evil.example']) {
      const bad = await ask(other);
      await note(!bad.headers['access-control-allow-origin'], `Origin ${other} → ${bad.status}, Allow-Origin ${bad.headers['access-control-allow-origin'] ?? '없음'}`);
    }
  });

step('return-path', '돌아갈 주소에 바깥 주소를 넣으면',
  '로그인 뒤 돌아갈 곳(return)은 화면 안의 경로만 받아요. 바깥 주소를 넣으면 화면 첫 주소(/)로만 가요. Keycloak엔 이미 로그인돼 있어 폼 없이 돌아오고, 다시 로그인한 셈이라 새 세션이 생겨요.',
  async (note) => {
    const outside = [];
    // 바깥 주소(evil.example)로 가는 요청이 하나라도 있으면 막고 센다. return 값에 든 글자가 아니라 이동한 호스트로 본다
    const toEvil = (u) => u.hostname === 'evil.example' || u.hostname.endsWith('.evil.example');
    await ctx.route(toEvil, (route) => { outside.push(route.request().url()); return route.abort(); });
    const before = await myRow(ctx, 'demo');
    for (const evil of ['https://evil.example/steal', '//evil.example/steal', '/\\evil.example']) {
      await Promise.all([
        page.waitForURL((u) => u.origin === APP, { timeout: 15_000 }),
        page.goto(`${APPS.demo.api}/oauth2/authorization/keycloak?return=${encodeURIComponent(evil)}`),
      ]);
      await page.waitForLoadState('load');
      await note(page.url() === `${APP}/` && outside.length === 0, `return=${evil} → ${page.url()}`);
      if (!HEADLESS) await sleep(900);
    }
    await ctx.unroute(toEvil);
    const after = await myRow(ctx, 'demo');
    await note(Boolean(after && before && after.id !== before.id && !rowExists('demo', before.id)), '새 세션 행이 생기고 예전 행은 지워짐');
    const audit = await auditLine('demo', `[KSS] 세션 끝남 reason=relogin session=${before?.id}`);
    if (audit !== null) await note(audit, `감사 로그 "세션 끝남 reason=relogin" ${audit ? '있음' : '없음'}`);
  });

step('local-verify', '요청마다 Keycloak을 부르지 않음',
  'at가 살아 있는 동안은 앱이 토큰 서명·기한을 스스로 검사해요(introspect·UserInfo 안 씀). "내 정보"를 20번 불러도 Keycloak에는 한 번도 안 가요(Keycloak 이벤트로 셈).',
  async (note) => {
    st.kcSid = (await myRow(ctx, 'demo')).kcSid;
    const since = Date.now();
    const statuses = [];
    for (let i = 0; i < 20; i++) statuses.push((await frontFetch(page, apiUrl('demo', '/api/me'), {}, { app: 'demo', label: `GET /api/me (${i + 1}/20)` })).status);
    await sleep(500);
    const events = await kcEvents(st.kcSid, since);
    await note(statuses.every((s) => s === 200), `/api/me 20번 → 모두 ${[...new Set(statuses)].join(',')}`);
    await note(events.length === 0, `그동안 Keycloak 호출 ${events.length}번`);
  });

step('refresh', 'at가 끝나도 계속 됨 (토큰 갱신)',
  'at 쿠키를 지워 "at가 만료돼 브라우저가 버린" 상태를 만들어요. 다음 요청에서 앱이 DB의 리프레시 토큰과 client secret으로 Keycloak에서 새 토큰을 받아, 사용자는 모르게 그대로 200이 와요.',
  async (note) => {
    const rowBefore = await myRow(ctx, 'demo');
    const atBefore = (await cookie(ctx, 'demo', 'at')).value;
    await dropAt(ctx, 'demo');
    await note(!(await cookie(ctx, 'demo', 'at')), 'at 쿠키를 지웠어요');
    const r = await press(page, 'demo', 'me');
    st.lastRefresh = Date.now();
    const atAfter = await cookie(ctx, 'demo', 'at');
    const rowAfter = await myRow(ctx, 'demo');
    await note(r.status === 200, `"내 정보" → ${r.status}`);
    await note(Boolean(atAfter && atAfter.value !== atBefore), '새 at 쿠키를 받음');
    await note(Boolean(rowAfter.refreshedAt && rowAfter.refreshedAt !== rowBefore.refreshedAt), `DB 행 refreshed_at ${rowBefore.refreshedAt || '(없음)'} → ${rowAfter.refreshedAt}`);
  });

step('concurrent-background', '동시에 여러 번 · 주기 호출',
  '화면이 동시에 5번 불러도 Keycloak 갱신은 1번만 해요. 화면이 알아서 주기적으로 부르는 요청(X-Background: 1)은 갱신하지 않고 401만 줘요. 사람이 누른 다음 요청은 다시 됩니다.',
  async (note) => {
    await pastReuseWindow(note, st.lastRefresh);
    await dropAt(ctx, 'demo');
    const since = Date.now();
    const statuses = await page.evaluate(async (url) =>
      Promise.all(Array.from({ length: 5 }, () => fetch(url, { credentials: 'include' }).then((r) => r.status))), apiUrl('demo', '/api/me'));
    await sleep(500);
    const refreshes = await kcEvents(st.kcSid, since, 'REFRESH_TOKEN');
    st.lastRefresh = Date.now();
    await note(statuses.every((s) => s === 200) && refreshes.length === 1, `at 없이 동시에 5번 → ${statuses.join(',')}, Keycloak 갱신 ${refreshes.length}번`);
    await dropAt(ctx, 'demo');
    const bg = await frontFetch(page, apiUrl('demo', '/api/me'), { headers: { 'X-Background': '1' } }, { app: 'demo', label: 'GET /api/me (X-Background: 1)' });
    await note(bg.status === 401 && (await myRow(ctx, 'demo')) !== null, `at 없이 X-Background: 1 → ${bg.status}, 세션 행은 그대로`);
    if (!HEADLESS) await sleep(1500);
    const again = await press(page, 'demo', 'me');
    await note(again.status === 200, `사람이 누른 "내 정보" → ${again.status}`);
  });

if (OUTAGE) {
  step('outage-down', 'Keycloak이 멈추면',
    'Keycloak 컨테이너를 실제로 멈춰요. 갱신이 필요한 요청은 503 KEYCLOAK_UNAVAILABLE을 받고, 세션 행과 쿠키는 그대로 남아요(Keycloak이 돌아오면 이어서 씀).',
    async (note) => {
      await pastReuseWindow(note, st.lastRefresh);
      await note(null, 'Keycloak 컨테이너를 멈췄어요 (docker compose stop keycloak)');
      stopKeycloak();
      await dropAt(ctx, 'demo');
      const r = await press(page, 'demo', 'me');
      await note(r.status === 503 && code(r) === 'KEYCLOAK_UNAVAILABLE', `at 없이 "내 정보" → ${r.status} ${code(r)}`);
      await note((await myRow(ctx, 'demo')) !== null && Boolean(await cookie(ctx, 'demo', 'sid')), '세션 행·sid 쿠키 그대로');
    });
  step('outage-up', 'Keycloak이 돌아오면',
    'Keycloak을 다시 띄워요(몇십 초 걸려요). 같은 세션으로 다음 요청이 그대로 200이 돼요.',
    async (note) => {
      await note(null, 'Keycloak을 다시 띄우는 중…');
      startKeycloak();
      await note(null, 'Keycloak이 떴어요');
      const r = await press(page, 'demo', 'me');
      await note(r.status === 200, `"내 정보" → ${r.status}`);
    });
}

step('tampered-at', '서명이 망가진 at',
  'at 쿠키의 서명 끝 몇 글자만 바꿔 넣어요. 앱은 서명 검사에서 거절해 401을 주고, 이 세션(행·쿠키)을 끝내요. 위조 토큰으로는 Keycloak 갱신도 부르지 않아요.',
  async (note) => {
    const good = await cookie(ctx, 'demo', 'at');
    const broken = good.value.slice(0, -4) + (good.value.slice(-4) === 'AAAA' ? 'BBBB' : 'AAAA');
    const rowId = (await myRow(ctx, 'demo')).id;
    const since = Date.now();
    await ctx.addCookies([{ name: good.name, value: broken, url: 'https://api.kss.test/', secure: true, httpOnly: true, sameSite: 'Lax', expires: good.expires }]);
    await note(null, 'at 쿠키 서명 끝 4글자를 바꿨어요');
    const r = await press(page, 'demo', 'me');
    await sleep(500);
    const refreshes = await kcEvents(st.kcSid, since, 'REFRESH_TOKEN');
    await note(r.status === 401, `"내 정보" → ${r.status} ${code(r)}`);
    await note(!rowExists('demo', rowId) && (await cookiesOf(ctx, 'demo')).length === 0, '세션 행·demo 쿠키 지워짐');
    await note(refreshes.length === 0, `Keycloak 갱신 ${refreshes.length}번`);
    const audit = await auditLine('demo', `[KSS] 세션 끝남 reason=invalid_token session=${rowId}`);
    if (audit !== null) await note(audit, `감사 로그 "세션 끝남 reason=invalid_token" ${audit ? '있음' : '없음'}`);
  });

step('sso', '두 번째 앱 demo2: 로그인 폼 없이 (SSO)',
  '앞 단계에서 demo 세션이 끝났으니 demo에 다시 로그인해요(Keycloak엔 로그인돼 있어 폼 없음). 같은 Keycloak을 쓰는 다른 앱 demo2(:8444)도 로그인 버튼만 누르면 폼 없이 들어와요. 두 앱 토큰은 같은 Keycloak 세션(sid)을 가리키고, 쿠키 이름은 앱마다 따로예요.',
  async (note) => {
    if (new URL(page.url()).pathname !== '/') await page.goto(`${APP}/`);
    const demoForm = await pressLogin(page, 'demo');
    await note(!demoForm, `demo "로그인" → ${demoForm ? 'Keycloak 폼이 나옴' : '폼 없이 바로 돌아옴'}`);
    if (!HEADLESS) await sleep(900);
    const formShown = await pressLogin(page, 'demo2');
    await note(!formShown, `demo2 "로그인" → ${formShown ? 'Keycloak 폼이 나옴' : '폼 없이 바로 돌아옴'}`);
    const sidOf = async (app) => jwtPayload((await cookie(ctx, app, 'at')).value).sid;
    const [s1, s2] = [await sidOf('demo'), await sidOf('demo2')];
    await note(Boolean(s1) && s1 === s2, `두 앱 토큰의 Keycloak 세션(sid) ${s1 === s2 ? '같음' : '다름'}`);
    await note(null, `demo2 쿠키 ${(await cookiesOf(ctx, 'demo2')).map((c) => c.name).sort().join(', ')}`);
    const me = await press(page, 'demo2', 'me');
    await note(me.status === 200 && json(me.text)?.username === 'alice', `demo2 "내 정보" → ${me.status}, username=${json(me.text)?.username}`);
    st.demo2Row = await myRow(ctx, 'demo2');
    st.kcSidNow = s1;
  });

step('logout', 'demo 로그아웃',
  'demo의 "로그아웃"은 CSRF 토큰을 숨은 칸(_csrf)에 넣은 폼 POST(화면 이동)예요. 앱이 서버끼리 Keycloak 로그아웃을 하고, 화면의 로그아웃 주소(/logged-out)로 보내요. '
  + '응답이 쿠키 넷(sid·at·csrf·login)을 Max-Age=0으로 지우고, DB 행과 Keycloak SSO 세션도 끝나요.',
  async (note) => {
    const demoRow = await myRow(ctx, 'demo');
    const logoutResponse = page.waitForResponse((r) => r.url() === apiUrl('demo', '/logout') && r.request().method() === 'POST');
    await clickAndLand(page, '#demo-logout');
    const res = await logoutResponse;
    const req = res.request();
    await note(req.isNavigationRequest() && /(^|&)_csrf=[^&]+/.test(req.postData() ?? ''), `POST /logout: 화면 이동(폼), 숨은 칸 _csrf ${/(^|&)_csrf=[^&]+/.test(req.postData() ?? '') ? '있음' : '없음'}`);
    const cleared = (await res.headersArray()).filter((h) => h.name.toLowerCase() === 'set-cookie' && /Max-Age=0/i.test(h.value))
      .map((h) => h.value.split('=')[0].replace(/^__Host-demo_/, ''));
    await note(cleared.length === 4 && ['sid', 'at', 'csrf', 'login'].every((n) => cleared.includes(n)), `응답 Set-Cookie Max-Age=0: ${cleared.join(', ')} (${cleared.length}개), 상태 ${res.status()}`);
    await note(page.url() === `${APP}/logged-out`, `지금 화면 ${page.url()} ("로그아웃됐습니다")`);
    await note((await cookiesOf(ctx, 'demo')).length === 0, 'demo 쿠키 모두 지워짐');
    await note(!rowExists('demo', demoRow.id), 'demo DB 세션 행 지워짐');
    const kcGone = await waitFor(async () => !(await kcSessions(aliceId)).some((s) => s.id === st.kcSidNow));
    await note(Boolean(kcGone), `Keycloak SSO 세션 ${kcGone ? '끝남' : '남아 있음'}`);
    const audit = await auditLine('demo', `[KSS] 세션 끝남 reason=logout session=${demoRow.id}`);
    if (audit !== null) await note(audit, `감사 로그 "세션 끝남 reason=logout" ${audit ? '있음' : '없음'}`);
  });

step('backchannel', 'demo2도 따라서 끝남 (back-channel 로그아웃)',
  'Keycloak이 demo2에게 서버끼리 "이 세션 끝났다"를 보내(back-channel) demo2 DB 행도 지워져요. 브라우저의 demo2 at는 남은 시간(최대 60초)까지만 통하고, at가 끝나면 갱신 없이 401이에요.',
  async (note) => {
    const gone = await waitFor(() => !rowExists('demo2', st.demo2Row.id));
    await note(Boolean(gone), `demo2 DB 세션 행 ${gone ? '지워짐' : '남아 있음'}`);
    const audit = await auditLine('demo2', `[KSS] 세션 끝남 reason=backchannel_logout session=${st.demo2Row.id}`);
    if (audit !== null) await note(audit, `demo2 감사 로그 "reason=backchannel_logout" ${audit ? '있음' : '없음'}`);
    const still = await press(page, 'demo2', 'me');
    await note(still.status === 200, `at가 남아 있는 demo2 "내 정보" → ${still.status} (설계대로, 최대 60초)`);
    if (!HEADLESS) await sleep(1500);
    await dropAt(ctx, 'demo2');
    const since = Date.now();
    const after = await press(page, 'demo2', 'me');
    await sleep(500);
    const refreshes = await kcRefreshEvents('demo2', since);
    await note(after.status === 401 && refreshes.length === 0, `at가 끝난 demo2 "내 정보" → ${after.status}, Keycloak 갱신 ${refreshes.length}번`);
  });

step('login-again', '다시 로그인하면 폼이 다시 나옴',
  'Keycloak SSO 세션이 정말 끝났는지 봐요. demo "로그인"을 누르면 이번엔 Keycloak 로그인 폼이 다시 나와야 해요.',
  async (note) => {
    if (new URL(page.url()).origin !== APP) await page.goto(`${APP}/`);
    const formShown = await pressLogin(page, 'demo');
    await note(formShown, `demo "로그인" → ${formShown ? 'Keycloak 로그인 폼이 다시 나옴' : '폼 없이 들어감'}`);
  });

step('logs', '로그에 토큰·sid 원문이 없음',
  '두 앱 로그 전체에서 JWT 모양(eyJ…)과, 이번에 앱이 내린 sid 쿠키 값이 하나도 없어야 해요. 세션이 끝날 때마다 사유(reason=)가 남았는지도 봐요.',
  async (note) => {
    for (const app of ['demo', 'demo2']) {
      const file = APPS[app].log;
      if (!file || !fs.existsSync(file)) {
        await note(null, `${app} 로그 파일을 안 줘서 못 봐요(KSS_${app === 'demo' ? 'DEMO' : 'DEMO2'}_LOG)`);
        continue;
      }
      const log = fs.readFileSync(file, 'utf8');
      const jwtLike = (log.match(/eyJ[A-Za-z0-9_-]{10,}/g) ?? []).length;
      const rawSid = [...seenSids].filter((v) => log.includes(v)).length;
      const reasons = [...new Set((log.match(/\[KSS\] 세션 끝남 reason=([a-z_]+)/g) ?? []).map((l) => l.split('reason=')[1]))];
      await note(jwtLike === 0 && rawSid === 0 && seenSids.size > 0, `${app} 로그: JWT 모양 ${jwtLike}개, sid 원문 ${rawSid}개 (이번 sid ${seenSids.size}개와 비교)`);
      await note(reasons.length > 0, `${app} 로그의 세션 끝남 사유: ${reasons.join(', ') || '없음'}`);
    }
    await note(null, '실제 시간을 기다리는 것(at 만료 95초, 미사용 2분, 절대 상한 3분)은 feature-walkthrough.mjs --slow로 봐요');
  });

if (NOTES?.summary) {
  step('notes-summary', NOTES.summary.title ?? '요약', NOTES.summary.look ?? '', async (note) => {
    for (const line of NOTES.summary.lines ?? []) await note(null, line);
  });
}
if (NOTES?.steps) {
  const unknown = Object.keys(NOTES.steps).filter((k) => !steps.some((s) => s.key === k));
  if (unknown.length) console.error(`KSS_TOUR_NOTES에 없는 단계 키: ${unknown.join(', ')} (있는 키: ${steps.map((s) => s.key).join(', ')})`);
}

// ---------------------------------------------------------------- 돌리기

let failed = 0;
let passed = 0;
let exitCode = 0;
async function cleanUp() {
  if (keycloakStopped) {
    try { startKeycloak(); } catch { console.error('Keycloak을 다시 띄우지 못했습니다: integration-tests/local-stack.sh up'); }
  }
}
process.once('SIGINT', async () => {
  console.error('\n멈춤 요청을 받았습니다. 정리합니다');
  await cleanUp();
  process.exit(130);
});
let closedByUser = false;
browser.on('disconnected', async () => {
  if (closedByUser) return;
  console.error('\n브라우저 창이 닫혀 끝냅니다');
  await cleanUp();
  process.exit(0);
});
if (SHOTS) fs.mkdirSync(SHOTS, { recursive: true });
try {
  for (let i = 0; i < steps.length; i++) {
    const s = steps[i];
    board = { n: i + 1, total: steps.length, title: s.title, look: s.look, results: [], state: 'running', auto: AUTO_MS !== null,
      notesLabel: NOTES?.label, notes: NOTES?.steps?.[s.key] ?? [] };
    console.log(`\n== ${i + 1}/${steps.length} ${s.title}`);
    await render(page);
    const note = async (ok, text) => {
      board.results.push({ ok, text });
      if (ok === true) passed++;
      if (ok === false) failed++;
      console.log(`${ok === null ? 'INFO' : ok ? 'PASS' : 'FAIL'} ${text}`);
      await render(page);
    };
    try {
      await s.run(note);
    } catch (e) {
      await note(false, `멈춤: ${String(e?.message ?? e).split('\n')[0]}`);
      throw e;
    } finally {
      board.state = i === steps.length - 1 ? 'done' : 'waiting';
      await render(page);
      if (SHOTS) await page.screenshot({ path: path.join(SHOTS, `${String(i + 1).padStart(2, '0')}.png`) }).catch(() => {});
    }
    await waitNext(page);
  }
} catch (e) {
  exitCode = 2;
  console.error('\n중간에 멈춤:', e);
  if (AUTO_MS === null) await waitNext(page).catch(() => {}); // 사람이 멈춘 화면을 볼 수 있게 "다음"을 누를 때까지 둔다
} finally {
  await cleanUp();
  console.log(`\n${passed}개 통과, ${failed}개 실패${exitCode ? ' (중간에 멈춤)' : ''} (${CHROME ? 'Chrome' : 'Chromium'} ${browser.version()})`);
  closedByUser = true;
  await browser.close();
  process.exit(exitCode || (failed ? 1 : 0));
}
