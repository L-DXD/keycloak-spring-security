package com.ids.keycloak.security.sample.e2e;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.net.ssl.SSLContext;

import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.entity.UrlEncodedFormEntity;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicNameValuePair;
import org.apache.hc.core5.ssl.SSLContexts;
import org.apache.hc.core5.util.Timeout;

/**
 * 브라우저처럼 움직이는 HTTP 클라이언트 (docs/v3/03-검증-환경.md 4절).
 * <ul>
 *   <li>리다이렉트를 저절로 따라가지 않는다. 302 주소와 Set-Cookie를 하나씩 확인할 수 있다</li>
 *   <li>쿠키 상자를 직접 가진다. 브라우저 규칙대로 Domain·Path·Secure·Max-Age를 지킨다</li>
 *   <li>샘플 앱 HTTPS는 테스트 CA만 믿는다</li>
 * </ul>
 * 이름(*.kss.test)은 테스트 JVM의 hosts 파일(jdk.net.hosts.file)로 127.0.0.1에 풀린다.
 */
public class BrowserClient implements AutoCloseable {

    /** 화면 주소. 화면에서 부른 요청처럼 보일 때 Origin으로 쓴다. */
    public static final String FRONTEND_ORIGIN = "https://app.kss.test";

    private static final Pattern LOGIN_FORM = Pattern.compile("<form\\b[^>]*\\bid=\"kc-form-login\"[^>]*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern ACTION = Pattern.compile("\\baction=\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);

    private final CloseableHttpClient http;
    private final List<StoredCookie> jar = new ArrayList<>();
    private final List<Exchange> history = new ArrayList<>();

    public BrowserClient(Path caCertificate) {
        this.http = HttpClients.custom()
            .disableRedirectHandling()
            .disableCookieManagement()
            .disableAutomaticRetries()
            .setConnectionManager(PoolingHttpClientConnectionManagerBuilder.create()
                .setTlsSocketStrategy(new DefaultClientTlsStrategy(trusting(caCertificate)))
                .setMaxConnPerRoute(20)
                .setMaxConnTotal(40)
                .build())
            .setDefaultRequestConfig(RequestConfig.custom()
                .setResponseTimeout(Timeout.ofSeconds(30))
                .build())
            .build();
    }

    // ---- 요청 ----

    public Exchange get(String url, Header... headers) {
        return send("GET", url, null, headers);
    }

    public Exchange postForm(String url, Map<String, String> form, Header... headers) {
        List<NameValuePair> pairs = form.entrySet().stream()
            .map(e -> (NameValuePair) new BasicNameValuePair(e.getKey(), e.getValue()))
            .toList();
        return send("POST", url, new UrlEncodedFormEntity(pairs, StandardCharsets.UTF_8), headers);
    }

    public Exchange postJson(String url, String json, Header... headers) {
        return send("POST", url, new StringEntity(json, ContentType.APPLICATION_JSON), headers);
    }

    /** 302면 Location을 GET으로 따라간다. 마지막 응답을 돌려준다. */
    public Exchange follow(Exchange exchange) {
        Exchange current = exchange;
        for (int i = 0; i < 10 && current.isRedirect(); i++) {
            current = get(current.location().toString());
        }
        return current;
    }

    /**
     * E2E-04: Keycloak 로그인 화면을 HTTP로 채워 로그인한다.
     * 앱의 콜백(/login/oauth2/code/keycloak) 응답까지 받고 멈춘다. 그 뒤 리다이렉트는 부른 쪽이 본다.
     */
    public Login login(SampleApps.Running app, String username, String password) {
        return login(app, "/oauth2/authorization/keycloak", username, password);
    }

    /** 로그인 시작 주소(예: {@code /oauth2/authorization/keycloak?return=/items/3})를 정해 로그인한다. */
    public Login login(SampleApps.Running app, String startPath, String username, String password) {
        Login untilCallback = authorize(app, startPath, username, password);
        Exchange callback = get(untilCallback.submitted().location().toString());
        return new Login(untilCallback.start(), untilCallback.loginPage(), untilCallback.submitted(), callback);
    }

    /**
     * Keycloak 로그인 폼 제출까지만 한다. {@code submitted().location()}이 앱 콜백 주소다.
     * 콜백을 바꿔 부르는 시나리오(LOGIN-05)에서 쓴다. {@code callback()}은 {@code null}.
     */
    public Login authorize(SampleApps.Running app, String startPath, String username, String password) {
        Exchange start = get(app.url(startPath));
        if (!start.isRedirect()) {
            throw new AssertionError("로그인 시작이 302가 아니다: " + start);
        }
        Exchange page = follow(start);
        String action = loginFormAction(page);
        Map<String, String> form = new LinkedHashMap<>();
        form.put("username", username);
        form.put("password", password);
        form.put("credentialId", "");
        Exchange submitted = postForm(action, form);
        if (!submitted.isRedirect()) {
            throw new AssertionError("로그인 폼 제출 뒤 302가 아니다: " + submitted.status() + " " + abbreviate(submitted.body()));
        }
        return new Login(start, page, submitted, null);
    }

    /**
     * 이미 Keycloak에 로그인한 브라우저로 앱 로그인을 시작한다 (SSO). Keycloak이 로그인 화면 없이 바로 콜백으로 보내야 한다.
     * {@code loginPage()}는 Keycloak의 302 응답이다.
     */
    public Login ssoLogin(SampleApps.Running app, String startPath) {
        Exchange start = get(app.url(startPath));
        if (!start.isRedirect()) {
            throw new AssertionError("로그인 시작이 302가 아니다: " + start);
        }
        Exchange keycloak = get(start.location().toString());
        if (!keycloak.isRedirect() || !keycloak.location().toString().startsWith(app.url("/login/oauth2/code/"))) {
            throw new AssertionError("Keycloak이 로그인 화면 없이 콜백으로 보내지 않았다: " + keycloak + " " + abbreviate(keycloak.body()));
        }
        Exchange callback = get(keycloak.location().toString());
        return new Login(start, keycloak, keycloak, callback);
    }

    /** Keycloak 로그인 화면(#kc-form-login)의 제출 주소. */
    public static String loginFormAction(Exchange page) {
        Matcher form = LOGIN_FORM.matcher(page.body());
        if (page.status() != 200 || !form.find()) {
            throw new AssertionError("Keycloak 로그인 화면이 아니다: " + page.status() + " " + page.uri() + " " + abbreviate(page.body()));
        }
        Matcher action = ACTION.matcher(form.group());
        if (!action.find()) {
            throw new AssertionError("로그인 폼에 action이 없다");
        }
        return action.group(1).replace("&amp;", "&");
    }

    /**
     * 같은 쿠키로 GET {@code count}개를 한꺼번에 보낸다 (REFRESH-02: 탭 여러 개가 동시에 부르는 상황).
     * 모든 요청이 보내기 전의 쿠키 상자를 그대로 쓰고, 응답의 Set-Cookie는 다 받은 뒤 순서대로 상자에 넣는다.
     */
    public List<Exchange> getConcurrently(String url, int count, Header... headers) {
        URI uri = URI.create(url);
        String cookie = cookieHeader(uri);
        java.util.concurrent.CountDownLatch go = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(count);
        try {
            List<java.util.concurrent.Future<Exchange>> futures = new ArrayList<>();
            for (int i = 0; i < count; i++) {
                futures.add(pool.submit(() -> {
                    go.await();
                    return execute("GET", uri, null, cookie, headers);
                }));
            }
            go.countDown();
            List<Exchange> exchanges = new ArrayList<>();
            for (java.util.concurrent.Future<Exchange> future : futures) {
                exchanges.add(future.get(60, java.util.concurrent.TimeUnit.SECONDS));
            }
            for (Exchange exchange : exchanges) {
                remember(exchange);
            }
            return exchanges;
        } catch (Exception e) {
            throw new IllegalStateException("동시 요청 실패: " + e.getMessage(), e);
        } finally {
            pool.shutdownNow();
        }
    }

    private Exchange send(String method, String url, org.apache.hc.core5.http.HttpEntity entity, Header... headers) {
        URI uri = URI.create(url);
        Exchange exchange = execute(method, uri, entity, cookieHeader(uri), headers);
        remember(exchange);
        return exchange;
    }

    private Exchange execute(String method, URI uri, org.apache.hc.core5.http.HttpEntity entity, String cookie, Header... headers) {
        HttpUriRequestBase request = new HttpUriRequestBase(method, uri);
        for (Header header : headers) {
            request.addHeader(header);
        }
        if (!cookie.isEmpty()) {
            request.addHeader("Cookie", cookie);
        }
        if (entity != null) {
            request.setEntity(entity);
        }
        try {
            return http.execute(request, response -> {
                String body = response.getEntity() == null ? "" : EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
                return new Exchange(method, uri, response.getCode(), List.of(response.getHeaders()), body);
            });
        } catch (IOException e) {
            throw new IllegalStateException(method + " " + uri + " 실패: " + e.getMessage(), e);
        }
    }

    private void remember(Exchange exchange) {
        for (String setCookie : exchange.headers("Set-Cookie")) {
            store(exchange.uri(), setCookie);
        }
        history.add(exchange);
    }

    // ---- 쿠키 상자 ----

    /** 지금 상자에 있는 쿠키 (만료 지난 것 빼고). */
    public List<StoredCookie> cookies() {
        removeExpired();
        return Collections.unmodifiableList(jar);
    }

    public Optional<StoredCookie> cookie(String host, String name) {
        return cookies().stream().filter(c -> c.name().equals(name) && c.matchesHost(host)).findFirst();
    }

    public void removeCookie(String host, String name) {
        jar.removeIf(c -> c.name().equals(name) && c.matchesHost(host));
    }

    /** 쿠키 값만 바꾼다 (속성은 그대로). 토큰을 망가뜨리는 시나리오(REQ-04)에서 쓴다. */
    public void replaceCookieValue(String host, String name, String value) {
        StoredCookie old = cookie(host, name).orElseThrow(() -> new AssertionError(name + " 쿠키가 없다"));
        jar.remove(old);
        jar.add(new StoredCookie(old.name(), value, old.domain(), old.hostOnly(), old.path(), old.secure(), old.httpOnly(),
            old.sameSite(), old.expiresAt(), old.raw()));
    }

    public List<Exchange> history() {
        return Collections.unmodifiableList(history);
    }

    private String cookieHeader(URI uri) {
        removeExpired();
        boolean secure = "https".equalsIgnoreCase(uri.getScheme());
        String path = (uri.getRawPath() == null || uri.getRawPath().isEmpty()) ? "/" : uri.getRawPath();
        return jar.stream()
            .filter(c -> c.matchesHost(uri.getHost()))
            .filter(c -> path.startsWith(c.path()))
            .filter(c -> secure || !c.secure())
            .map(c -> c.name() + "=" + c.value())
            .collect(Collectors.joining("; "));
    }

    private void store(URI uri, String header) {
        StoredCookie cookie = StoredCookie.parse(uri, header);
        // 브라우저는 http 응답이 준 Secure 쿠키를 받지 않는다
        if (cookie.secure() && !"https".equalsIgnoreCase(uri.getScheme())) {
            return;
        }
        jar.removeIf(c -> c.name().equals(cookie.name()) && c.domain().equals(cookie.domain()) && c.path().equals(cookie.path()));
        if (!cookie.isExpired(Instant.now())) {
            jar.add(cookie);
        }
    }

    private void removeExpired() {
        Instant now = Instant.now();
        jar.removeIf(c -> c.isExpired(now));
    }

    @Override
    public void close() throws IOException {
        http.close();
    }

    private static SSLContext trusting(Path caCertificate) {
        try (InputStream in = Files.newInputStream(caCertificate)) {
            Certificate ca = CertificateFactory.getInstance("X.509").generateCertificate(in);
            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            trustStore.load(null, null);
            trustStore.setCertificateEntry("kss-test-ca", ca);
            return SSLContexts.custom().loadTrustMaterial(trustStore, null).build();
        } catch (Exception e) {
            throw new IllegalStateException("테스트 CA를 읽지 못했다: " + caCertificate, e);
        }
    }

    static String abbreviate(String text) {
        return text.length() <= 300 ? text : text.substring(0, 300) + "...";
    }

    // ---- 값 ----

    /** 요청 하나와 응답. */
    public record Exchange(String method, URI uri, int status, List<Header> rawHeaders, String body) {

        public List<String> headers(String name) {
            return rawHeaders.stream().filter(h -> h.getName().equalsIgnoreCase(name)).map(Header::getValue).toList();
        }

        public Optional<String> header(String name) {
            return headers(name).stream().findFirst();
        }

        public boolean isRedirect() {
            return status >= 300 && status < 400 && header("Location").isPresent();
        }

        /** Location을 요청 주소 기준으로 푼 것. */
        public URI location() {
            return uri.resolve(header("Location").orElseThrow(() -> new AssertionError("Location이 없다: " + this)));
        }

        /** 이 응답이 준 Set-Cookie 가운데 이름이 같은 것. */
        public Optional<StoredCookie> setCookie(String name) {
            return headers("Set-Cookie").stream().map(h -> StoredCookie.parse(uri, h)).filter(c -> c.name().equals(name)).findFirst();
        }

        @Override
        public String toString() {
            return method + " " + uri + " -> " + status + header("Location").map(l -> " Location: " + l).orElse("");
        }
    }

    /** 로그인 한 번의 단계별 응답 (E2E-04). */
    public record Login(Exchange start, Exchange loginPage, Exchange submitted, Exchange callback) {
    }

    /** 쿠키 상자 안의 쿠키 하나. 속성을 그대로 들고 있어 테스트가 볼 수 있다. */
    public record StoredCookie(String name, String value, String domain, boolean hostOnly, String path,
                               boolean secure, boolean httpOnly, String sameSite, Instant expiresAt, String raw) {

        static StoredCookie parse(URI uri, String header) {
            String[] parts = header.split(";");
            int eq = parts[0].indexOf('=');
            String name = parts[0].substring(0, eq).trim();
            String value = parts[0].substring(eq + 1).trim();
            String domain = null;
            String path = null;
            boolean secure = false;
            boolean httpOnly = false;
            String sameSite = null;
            Instant expiresAt = null;
            Long maxAge = null;
            for (int i = 1; i < parts.length; i++) {
                String part = parts[i].trim();
                int at = part.indexOf('=');
                String key = (at < 0 ? part : part.substring(0, at)).trim().toLowerCase(Locale.ROOT);
                String val = at < 0 ? "" : part.substring(at + 1).trim();
                switch (key) {
                    case "domain" -> domain = val.startsWith(".") ? val.substring(1) : val;
                    case "path" -> path = val;
                    case "secure" -> secure = true;
                    case "httponly" -> httpOnly = true;
                    case "samesite" -> sameSite = val;
                    case "max-age" -> maxAge = Long.parseLong(val);
                    case "expires" -> expiresAt = ZonedDateTime.parse(val, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant();
                    default -> {
                    }
                }
            }
            if (maxAge != null) {
                expiresAt = Instant.now().plusSeconds(maxAge);
            }
            boolean hostOnly = domain == null || domain.isEmpty();
            return new StoredCookie(name, value, hostOnly ? uri.getHost() : domain.toLowerCase(Locale.ROOT), hostOnly,
                path == null || path.isEmpty() ? defaultPath(uri) : path, secure, httpOnly, sameSite, expiresAt, header);
        }

        private static String defaultPath(URI uri) {
            String p = uri.getPath();
            if (p == null || p.isEmpty() || !p.startsWith("/")) {
                return "/";
            }
            int last = p.lastIndexOf('/');
            return last == 0 ? "/" : p.substring(0, last);
        }

        boolean matchesHost(String host) {
            String h = Objects.requireNonNull(host).toLowerCase(Locale.ROOT);
            return hostOnly ? h.equals(domain) : (h.equals(domain) || h.endsWith("." + domain));
        }

        boolean isExpired(Instant now) {
            return expiresAt != null && !expiresAt.isAfter(now);
        }

        /** 세션 쿠키(브라우저를 닫으면 사라짐)인가. */
        public boolean isSessionCookie() {
            return expiresAt == null;
        }
    }
}
