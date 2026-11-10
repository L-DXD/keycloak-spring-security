// 실제 브라우저(Chromium)로 쿠키 동작을 한 번 본다 (#91). Gradle 빌드에 묶지 않은 손 확인용이다.
// 준비: 샘플 앱(https://api.kss.test:8443)과 Keycloak(http://sso.kss.test:8180)을 띄운다 (docs/v3/03-검증-환경.md 7절).
// 실행: node integration-tests/browser/cookie-check.mjs   (Playwright가 깔린 Node)
//       모든 주소가 이 기계 안이다. HTTPS_PROXY 같은 프록시 환경 변수가 있으면 지우고 돌린다(브라우저가 그 프록시로 보낸다)
// 화면 app.kss.test와 다른 사이트 evil.test는 이 스크립트가 띄우는 작은 HTTPS 서버(127.0.0.1:9443)가 맡는다.
import https from 'node:https';
import fs from 'node:fs';
import { chromium } from 'playwright';

const API = process.env.KSS_API ?? 'https://api.kss.test:8443';
const APP = 'https://app.kss.test';
const EVIL = 'https://evil.test';
const USER = process.env.KSS_USER ?? 'alice';
const PASSWORD = process.env.KSS_PASSWORD ?? 'alice-test-password';
const TLS_DIR = process.env.KSS_TLS_DIR ?? 'integration-tests/servlet-app/build/e2e/tls';
const PAGE_PORT = 9443;

const results = [];
function check(id, name, ok, detail = '') {
  results.push({ id, name, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'} ${id} ${name}${detail ? ' — ' + detail : ''}`);
}

// 화면·다른 사이트 흉내: Host 머리글만 찍은 빈 페이지. 인증서는 샘플 앱 것을 빌려 쓴다(이름이 달라 인증서 오류는 아래에서 넘긴다)
const pages = https.createServer(
  { pfx: fs.readFileSync(`${TLS_DIR}/server.p12`), passphrase: 'changeit' },
  (req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!doctype html><title>${req.headers.host}</title><h1>${req.headers.host}${req.url}</h1>`);
  },
).listen(PAGE_PORT, '127.0.0.1');

const browser = await chromium.launch({
  // 주소(origin)는 https://app.kss.test 그대로 두고 연결만 이 기계로 보낸다
  args: [`--host-resolver-rules=MAP app.kss.test 127.0.0.1:${PAGE_PORT}, MAP evil.test 127.0.0.1:${PAGE_PORT}, MAP *.kss.test 127.0.0.1`],
});
// 테스트 CA는 브라우저가 모르므로 인증서 오류만 넘긴다. https 주소라서 Secure·__Host- 규칙은 그대로 적용된다
const context = await browser.newContext({ ignoreHTTPSErrors: true });

const tab = await context.newPage();

// 1. 로그인: 앱 → Keycloak 로그인 폼 → 앱 콜백 → 화면
await tab.goto(`${API}/oauth2/authorization/keycloak?return=/orders/1`);
await tab.fill('#username', USER);
await tab.fill('#password', PASSWORD);
await Promise.all([tab.waitForURL(`${APP}/**`), tab.click('#kc-login')]);
check('BR-01', '로그인 뒤 화면 주소 + 돌아갈 경로로 온다', tab.url() === `${APP}/orders/1`, tab.url());

const apiCookies = (await context.cookies(API)).filter((c) => c.name.startsWith('__Host-'));
const names = apiCookies.map((c) => c.name).sort();
check('BR-02', 'sid·at·csrf 쿠키가 있고 login 쿠키는 지워졌다',
  JSON.stringify(names) === JSON.stringify(['__Host-demo_at', '__Host-demo_csrf', '__Host-demo_sid']), names.join(','));
const attrsOk = apiCookies.every((c) => c.secure && c.httpOnly && c.sameSite === 'Lax' && c.path === '/' && c.domain === 'api.kss.test');
check('BR-03', '쿠키는 모두 Secure·HttpOnly·SameSite=Lax·Path=/·host 전용(Domain 없음)', attrsOk,
  apiCookies.map((c) => `${c.name}:${c.secure}/${c.httpOnly}/${c.sameSite}/${c.path}/${c.domain}`).join(' '));

// 2. 화면(같은 사이트, 다른 origin)에서 credentials 포함 fetch
const fromApp = await tab.evaluate(async (api) => {
  const me = await fetch(`${api}/api/me`, { credentials: 'include' });
  const csrf = await (await fetch(`${api}/api/csrf`, { credentials: 'include' })).json();
  const post = await fetch(`${api}/api/items`, {
    method: 'POST', credentials: 'include',
    headers: { 'Content-Type': 'application/json', 'X-XSRF-TOKEN': csrf.token },
    body: JSON.stringify({ name: 'browser' }),
  });
  const noToken = await fetch(`${api}/api/items`, {
    method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: '{}',
  });
  return { me: me.status, meBody: await me.json(), post: post.status, noToken: noToken.status, noTokenBody: await noToken.json() };
}, API);
check('BR-04', '화면에서 /api/me 200 (CORS 허용 + 쿠키 보냄)', fromApp.me === 200 && fromApp.meBody.username === USER, JSON.stringify(fromApp.meBody));
check('BR-05', '화면에서 CSRF 토큰과 POST 201', fromApp.post === 201, String(fromApp.post));
check('BR-06', '토큰 없는 POST는 403 INVALID_CSRF_TOKEN', fromApp.noToken === 403 && fromApp.noTokenBody.code === 'INVALID_CSRF_TOKEN',
  JSON.stringify(fromApp.noTokenBody));
const visible = await tab.evaluate(() => document.cookie);
check('BR-07', '화면 스크립트는 앱 쿠키를 못 읽는다', !visible.includes('__Host-'), JSON.stringify(visible));

// 3. 다른 사이트(evil.test)
const evil = await context.newPage();
await evil.goto(`${EVIL}/`);
const fromEvil = await evil.evaluate(async (api) => {
  try {
    const r = await fetch(`${api}/api/me`, { credentials: 'include' });
    return `status ${r.status}`;
  } catch (e) {
    return `blocked ${e.name}`;
  }
}, API);
check('BR-08', '다른 사이트의 fetch는 CORS로 막힌다', fromEvil.startsWith('blocked'), fromEvil);

// 다른 사이트에서 폼 POST(최상위 이동): SameSite=Lax라 쿠키가 안 가고, Origin 확인이 403
const [formResponse] = await Promise.all([
  evil.waitForResponse((r) => r.url() === `${API}/api/items`),
  evil.evaluate((api) => {
    const f = document.createElement('form');
    f.method = 'POST';
    f.action = `${api}/api/items`;
    f.innerHTML = '<input name="name" value="evil">';
    document.body.appendChild(f);
    f.submit();
  }, API),
]);
const formRequestCookie = (await formResponse.request().allHeaders())['cookie'] ?? '';
check('BR-09', '다른 사이트의 폼 POST에는 앱 쿠키가 안 가고 403', formResponse.status() === 403 && !formRequestCookie.includes('__Host-'),
  `status ${formResponse.status()}, cookie ${formRequestCookie ? '있음' : '없음'}`);

// 다른 사이트에서 링크로 GET(최상위 이동): Lax는 보낸다. GET은 상태를 바꾸지 않으므로 괜찮다
const evil2 = await context.newPage();
await evil2.goto(`${EVIL}/`);
const [linkResponse] = await Promise.all([
  evil2.waitForResponse((r) => r.url() === `${API}/api/me`),
  evil2.evaluate((api) => { location.href = `${api}/api/me`; }, API),
]);
check('BR-10', '다른 사이트 링크로 GET 이동하면 Lax 쿠키가 가서 200 (Lax의 정상 동작, GET은 상태를 안 바꿈)', linkResponse.status() === 200,
  String(linkResponse.status()));

// 4. 로그아웃: 화면 폼으로 POST /logout
await tab.bringToFront();
const token = await tab.evaluate(async (api) => (await (await fetch(`${api}/api/csrf`, { credentials: 'include' })).json()).token, API);
await Promise.all([
  tab.waitForURL(`${APP}/logged-out`),
  tab.evaluate(({ api, token }) => {
    const f = document.createElement('form');
    f.method = 'POST';
    f.action = `${api}/logout`;
    f.innerHTML = `<input name="_csrf" value="${token}">`;
    document.body.appendChild(f);
    f.submit();
  }, { api: API, token }),
]);
const after = (await context.cookies(API)).filter((c) => c.name.startsWith('__Host-')).map((c) => c.name);
check('BR-11', '로그아웃 뒤 화면 로그아웃 주소로 오고 앱 쿠키가 모두 지워진다', tab.url() === `${APP}/logged-out` && after.length === 0,
  `${tab.url()} ${after.join(',')}`);

const version = browser.version();
await browser.close();
pages.close();
const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed}/${results.length} 통과 (Chromium ${version})`);
process.exit(failed ? 1 : 0);
