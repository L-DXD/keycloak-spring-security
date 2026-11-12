package com.ids.keycloak.security.config;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import com.ids.keycloak.security.config.KeycloakSecurityConfigurationException.Problem;
import com.ids.keycloak.security.crypto.KeycloakKeyRing;

/**
 * 검사를 마친 라이브러리 설정 ({@code keycloak.security.*}). 만들어졌으면 값이 모두 맞다.
 * <p>
 * Spring Boot 스타터는 {@code KeycloakSecurityProperties}를 이것으로 바꿔 쓴다. Boot 없이 쓸 때는 {@link #builder()}로 만든다.
 * 설정 표: {@code docs/v3/01-설계.md} 6절.
 */
public class KeycloakSecuritySettings {

    /** 설정 이름 앞부분. */
    public static final String PREFIX = "keycloak.security";

    private static final Pattern APP_NAME = Pattern.compile("[A-Za-z0-9-]{1,32}");
    private static final Pattern KEY_ID = Pattern.compile("[A-Za-z0-9_-]{1,32}");
    private static final Pattern TABLE_NAME = Pattern.compile("[A-Za-z_][A-Za-z0-9_]{0,62}(\\.[A-Za-z_][A-Za-z0-9_]{0,62})?");
    private static final Pattern HEADER_NAME = Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]+");
    private static final Set<String> LOOPBACK_HOSTS = Set.of("localhost", "127.0.0.1", "[::1]", "::1");
    private static final Duration MAX_CLOCK_SKEW = Duration.ofMinutes(5);
    private static final Duration MIN_JWKS_REFETCH_INTERVAL = Duration.ofSeconds(10);
    private static final Duration MAX_JWKS_REFETCH_INTERVAL = Duration.ofHours(1);

    private final String registrationId;
    private final URI frontendBaseUrl;
    private final String frontendOrigin;
    private final String logoutSuccessPath;
    private final String cookieAppName;
    private final SessionStoreType sessionStore;
    private final String sessionTableName;
    private final Duration absoluteTimeout;
    private final Duration refreshReuseWindow;
    private final Duration cleanupInterval;
    private final Duration clockSkew;
    private final Duration jwksMinRefetchInterval;
    private final String requiredAudience;
    private final String backgroundHeader;
    private final String csrfEndpoint;
    private final boolean revokeRefreshTokenOnLocalLogout;
    private final List<String> permitAllPaths;
    private final KeycloakKeyRing keyRing;
    private final KeycloakLoggingSettings logging;
    private final int trustedProxyCount;

    protected KeycloakSecuritySettings(Builder b, URI frontendBaseUrl, KeycloakKeyRing keyRing) {
        this.registrationId = b.registrationId;
        this.frontendBaseUrl = frontendBaseUrl;
        this.frontendOrigin = originOf(frontendBaseUrl);
        this.logoutSuccessPath = b.logoutSuccessPath;
        this.cookieAppName = b.cookieAppName;
        this.sessionStore = b.sessionStore;
        this.sessionTableName = b.sessionTableName;
        this.absoluteTimeout = b.absoluteTimeout;
        this.refreshReuseWindow = b.refreshReuseWindow;
        this.cleanupInterval = b.cleanupInterval;
        this.clockSkew = b.clockSkew;
        this.jwksMinRefetchInterval = b.jwksMinRefetchInterval;
        this.requiredAudience = b.requiredAudience;
        this.backgroundHeader = b.backgroundHeader;
        this.csrfEndpoint = b.csrfEndpoint;
        this.revokeRefreshTokenOnLocalLogout = b.revokeRefreshTokenOnLocalLogout;
        this.permitAllPaths = List.copyOf(b.permitAllPaths);
        this.keyRing = keyRing;
        this.logging = b.logging;
        this.trustedProxyCount = b.trustedProxyCount;
    }

    public static Builder builder() {
        return new Builder();
    }

    // ---- 값 ----

    /** Spring OAuth2 Client 등록 id. 로그인 주소 {@code /oauth2/authorization/{id}}에 들어간다. 기본 {@code keycloak}. */
    public String registrationId() {
        return registrationId;
    }

    /** 화면 주소. 로그인 뒤·로그아웃 뒤 이리로 보낸다. */
    public URI frontendBaseUrl() {
        return frontendBaseUrl;
    }

    /** 화면 origin ({@code scheme://host[:port]}). CORS와 Origin 확인에 쓴다. */
    public String frontendOrigin() {
        return frontendOrigin;
    }

    /** 로그아웃 뒤 화면 경로. 기본 {@code /}. */
    public String logoutSuccessPath() {
        return logoutSuccessPath;
    }

    /** 로그아웃 뒤 화면 주소 = 화면 주소 + 로그아웃 뒤 경로. Keycloak client의 post logout redirect URI로 등록한다. */
    public URI frontendLogoutUrl() {
        String base = frontendBaseUrl.toString();
        if (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        return URI.create(base + logoutSuccessPath);
    }

    /** 쿠키 이름에 들어가는 앱 이름. 예: {@code demo} → {@code __Host-demo_sid}. */
    public String cookieAppName() {
        return cookieAppName;
    }

    public SessionStoreType sessionStore() {
        return sessionStore;
    }

    /** 세션 테이블 이름. 기본 {@code auth_session}. */
    public String sessionTableName() {
        return sessionTableName;
    }

    /** 로그인부터 이 시간이 지나면 갱신하지 않고 다시 로그인시킨다. 기본 12시간. */
    public Duration absoluteTimeout() {
        return absoluteTimeout;
    }

    /** 동시에 들어온 갱신 요청을 "방금 갱신함"으로 볼 시간. 기본 10초. */
    public Duration refreshReuseWindow() {
        return refreshReuseWindow;
    }

    /** 끝난 세션 행을 지우는 주기. 기본 10분. */
    public Duration cleanupInterval() {
        return cleanupInterval;
    }

    /** 토큰 시간 검사 오차. 기본 30초. */
    public Duration clockSkew() {
        return clockSkew;
    }

    /** 모르는 kid가 왔을 때 JWKS를 다시 받는 최소 간격. 기본 5분 (10초~1시간). */
    public Duration jwksMinRefetchInterval() {
        return jwksMinRefetchInterval;
    }

    /** 액세스 토큰 aud에 있어야 하는 값. 기본은 client id. */
    public String requiredAudience() {
        return requiredAudience;
    }

    /** 이 헤더가 붙은 요청은 갱신하지 않는다. 기본 {@code X-Background}. */
    public String backgroundHeader() {
        return backgroundHeader;
    }

    /** CSRF 토큰을 주는 주소. 기본 {@code /api/csrf}. */
    public String csrfEndpoint() {
        return csrfEndpoint;
    }

    /** 로컬 로그아웃 때 Keycloak 리프레시 토큰도 폐기하는가. 기본 끔 (D13). */
    public boolean revokeRefreshTokenOnLocalLogout() {
        return revokeRefreshTokenOnLocalLogout;
    }

    /** 로그인 없이 허용하는 경로. */
    public List<String> permitAllPaths() {
        return permitAllPaths;
    }

    public KeycloakKeyRing keyRing() {
        return keyRing;
    }

    /** MDC 로깅 설정. */
    public KeycloakLoggingSettings logging() {
        return logging;
    }

    /**
     * 앞에 있는 믿을 수 있는 프록시 수. 클라이언트 IP를 {@code X-Forwarded-For}에서 고를 때 쓴다. 기본 0(헤더를 보지 않고 연결 주소).
     * {@code -1}은 헤더의 첫 값을 그대로 믿는다(v2 호환, 위조될 수 있어 권하지 않음).
     */
    public int trustedProxyCount() {
        return trustedProxyCount;
    }

    /** 비밀값 없이 한 줄로. 기동 로그에 쓴다. */
    @Override
    public String toString() {
        return "KeycloakSecuritySettings[registration=" + registrationId + ", frontend=" + frontendBaseUrl
            + ", app=" + cookieAppName + ", store=" + sessionStore.name().toLowerCase(Locale.ROOT)
            + (sessionStore == SessionStoreType.JDBC ? "(" + sessionTableName + ")" : "")
            + ", absoluteTimeout=" + absoluteTimeout + ", activeKey=" + keyRing.activeKeyId() + "]";
    }

    private static String originOf(URI uri) {
        String origin = uri.getScheme().toLowerCase(Locale.ROOT) + "://" + uri.getHost().toLowerCase(Locale.ROOT);
        return uri.getPort() == -1 ? origin : origin + ":" + uri.getPort();
    }

    /**
     * 설정을 모아 검사한다. 잘못된 것이 있으면 {@link #build()}가 모두 모아 {@link KeycloakSecurityConfigurationException}을 던진다.
     */
    public static class Builder {

        private String registrationId = "keycloak";
        private String frontendBaseUrl;
        private String logoutSuccessPath = "/";
        private String cookieAppName;
        private SessionStoreType sessionStore = SessionStoreType.JDBC;
        private String sessionTableName = "auth_session";
        private Duration absoluteTimeout = Duration.ofHours(12);
        private Duration refreshReuseWindow = Duration.ofSeconds(10);
        private Duration cleanupInterval = Duration.ofMinutes(10);
        private Duration clockSkew = Duration.ofSeconds(30);
        private Duration jwksMinRefetchInterval = Duration.ofMinutes(5);
        private String requiredAudience;
        private String backgroundHeader = "X-Background";
        private String csrfEndpoint = "/api/csrf";
        private boolean revokeRefreshTokenOnLocalLogout;
        private List<String> permitAllPaths = List.of();
        private String activeKeyId;
        private Map<String, String> keys = Map.of();
        private KeycloakLoggingSettings logging = KeycloakLoggingSettings.defaults();
        private int trustedProxyCount;
        private final List<Problem> extraProblems = new ArrayList<>();

        protected Builder() {
        }

        public Builder registrationId(String registrationId) {
            this.registrationId = registrationId;
            return this;
        }

        public Builder frontendBaseUrl(String frontendBaseUrl) {
            this.frontendBaseUrl = frontendBaseUrl;
            return this;
        }

        public Builder logoutSuccessPath(String logoutSuccessPath) {
            this.logoutSuccessPath = logoutSuccessPath;
            return this;
        }

        public Builder cookieAppName(String cookieAppName) {
            this.cookieAppName = cookieAppName;
            return this;
        }

        public Builder sessionStore(SessionStoreType sessionStore) {
            this.sessionStore = sessionStore;
            return this;
        }

        public Builder sessionTableName(String sessionTableName) {
            this.sessionTableName = sessionTableName;
            return this;
        }

        public Builder absoluteTimeout(Duration absoluteTimeout) {
            this.absoluteTimeout = absoluteTimeout;
            return this;
        }

        public Builder refreshReuseWindow(Duration refreshReuseWindow) {
            this.refreshReuseWindow = refreshReuseWindow;
            return this;
        }

        public Builder cleanupInterval(Duration cleanupInterval) {
            this.cleanupInterval = cleanupInterval;
            return this;
        }

        public Builder clockSkew(Duration clockSkew) {
            this.clockSkew = clockSkew;
            return this;
        }

        public Builder jwksMinRefetchInterval(Duration jwksMinRefetchInterval) {
            this.jwksMinRefetchInterval = jwksMinRefetchInterval;
            return this;
        }

        public Builder requiredAudience(String requiredAudience) {
            this.requiredAudience = requiredAudience;
            return this;
        }

        public Builder backgroundHeader(String backgroundHeader) {
            this.backgroundHeader = backgroundHeader;
            return this;
        }

        public Builder csrfEndpoint(String csrfEndpoint) {
            this.csrfEndpoint = csrfEndpoint;
            return this;
        }

        public Builder revokeRefreshTokenOnLocalLogout(boolean revoke) {
            this.revokeRefreshTokenOnLocalLogout = revoke;
            return this;
        }

        public Builder permitAllPaths(List<String> permitAllPaths) {
            this.permitAllPaths = permitAllPaths == null ? List.of() : List.copyOf(permitAllPaths);
            return this;
        }

        public Builder activeKeyId(String activeKeyId) {
            this.activeKeyId = activeKeyId;
            return this;
        }

        /** 키 id → base64 키 (32바이트 이상). 표준·URL 안전 base64 둘 다 받는다. */
        public Builder keys(Map<String, String> keys) {
            this.keys = keys == null ? Map.of() : new LinkedHashMap<>(keys);
            return this;
        }

        public Builder logging(KeycloakLoggingSettings logging) {
            this.logging = logging;
            return this;
        }

        public Builder trustedProxyCount(int trustedProxyCount) {
            this.trustedProxyCount = trustedProxyCount;
            return this;
        }

        /** 이 밖에서 찾은 문제를 같이 알린다 (예: 스타터가 찾은 OAuth2 등록 누락). */
        public Builder problem(String property, String message) {
            this.extraProblems.add(new Problem(property, message));
            return this;
        }

        /**
         * @throws KeycloakSecurityConfigurationException 잘못된 설정이 하나라도 있으면
         */
        public KeycloakSecuritySettings build() {
            List<Problem> problems = new ArrayList<>(extraProblems);
            URI baseUrl = checkFrontend(problems);
            checkPath(problems, "frontend.logout-success-path", logoutSuccessPath);
            checkCookie(problems);
            checkSession(problems);
            checkToken(problems);
            if (isBlank(backgroundHeader) || !HEADER_NAME.matcher(backgroundHeader).matches()) {
                problems.add(issue("request.background-header", "HTTP 헤더 이름이 아닙니다"));
            }
            checkPath(problems, "csrf.endpoint", csrfEndpoint);
            for (int i = 0; i < permitAllPaths.size(); i++) {
                checkPath(problems, "permit-all-paths[" + i + "]", permitAllPaths.get(i));
            }
            checkLogging(problems);
            KeycloakKeyRing keyRing = checkCrypto(problems);
            if (!problems.isEmpty()) {
                throw new KeycloakSecurityConfigurationException(problems);
            }
            return create(baseUrl, keyRing);
        }

        /** 검사를 마친 값으로 설정을 만든다. 하위 클래스가 설정을 넓힐 때 바꾼다. */
        protected KeycloakSecuritySettings create(URI frontendBaseUrl, KeycloakKeyRing keyRing) {
            return new KeycloakSecuritySettings(this, frontendBaseUrl, keyRing);
        }

        private URI checkFrontend(List<Problem> problems) {
            if (isBlank(registrationId)) {
                problems.add(issue("registration-id", "필수입니다"));
            }
            if (isBlank(frontendBaseUrl)) {
                problems.add(issue("frontend.base-url", "필수입니다. 화면 주소를 넣으세요 (예: https://app.example.com)"));
                return null;
            }
            URI uri;
            try {
                uri = new URI(frontendBaseUrl.trim());
            } catch (URISyntaxException e) {
                problems.add(issue("frontend.base-url", "주소 형식이 아닙니다"));
                return null;
            }
            if (!uri.isAbsolute() || uri.getHost() == null) {
                problems.add(issue("frontend.base-url", "https://로 시작하는 절대 주소여야 합니다"));
                return null;
            }
            String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
            boolean loopback = LOOPBACK_HOSTS.contains(uri.getHost().toLowerCase(Locale.ROOT));
            if (!scheme.equals("https") && !(scheme.equals("http") && loopback)) {
                problems.add(issue("frontend.base-url", "https여야 합니다 (http는 localhost·127.0.0.1에서만 허용)"));
            }
            if (uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null) {
                problems.add(issue("frontend.base-url", "사용자 정보·쿼리·# 조각을 넣을 수 없습니다"));
            }
            return uri;
        }

        private void checkLogging(List<Problem> problems) {
            if (trustedProxyCount < -1) {
                problems.add(issue("trusted-proxy-count", "0 이상이어야 합니다 (-1은 X-Forwarded-For 첫 값을 그대로 믿는 v2 방식)"));
            }
            if (logging == null) {
                problems.add(issue("logging", "필수입니다"));
                return;
            }
            if (logging.maxQueryLength() < 1 || logging.maxQueryLength() > KeycloakLoggingSettings.MAX_LENGTH) {
                problems.add(issue("logging.max-query-length", "1에서 " + KeycloakLoggingSettings.MAX_LENGTH + " 사이여야 합니다"));
            }
            if (logging.maxUserAgentLength() < 1 || logging.maxUserAgentLength() > KeycloakLoggingSettings.MAX_LENGTH) {
                problems.add(issue("logging.max-user-agent-length", "1에서 " + KeycloakLoggingSettings.MAX_LENGTH + " 사이여야 합니다"));
            }
            for (int i = 0; i < logging.excludePatterns().size(); i++) {
                checkPath(problems, "logging.exclude-patterns[" + i + "]", logging.excludePatterns().get(i));
            }
        }

        private void checkCookie(List<Problem> problems) {
            if (isBlank(cookieAppName)) {
                problems.add(issue("cookie.app-name", "필수입니다 (스타터는 client id를 기본값으로 쓴다)"));
            } else if (!APP_NAME.matcher(cookieAppName).matches()) {
                problems.add(issue("cookie.app-name", "영문·숫자·-만 32자까지 됩니다 (쿠키 이름 __Host-{앱 이름}_sid에 들어갑니다)"));
            }
        }

        private void checkSession(List<Problem> problems) {
            if (sessionStore == null) {
                problems.add(issue("session.store", "jdbc 또는 memory여야 합니다"));
            }
            if (isBlank(sessionTableName) || !TABLE_NAME.matcher(sessionTableName).matches()) {
                problems.add(issue("session.table-name", "테이블 이름은 영문·숫자·_ 이고 스키마를 붙일 때는 schema.table 모양이어야 합니다"));
            }
            if (!isPositive(absoluteTimeout)) {
                problems.add(issue("session.absolute-timeout", "0보다 커야 합니다"));
            }
            if (refreshReuseWindow == null || refreshReuseWindow.isNegative()) {
                problems.add(issue("session.refresh-reuse-window", "0 이상이어야 합니다"));
            } else if (isPositive(absoluteTimeout) && refreshReuseWindow.compareTo(absoluteTimeout) >= 0) {
                problems.add(issue("session.refresh-reuse-window", "session.absolute-timeout보다 짧아야 합니다"));
            }
            if (!isPositive(cleanupInterval)) {
                problems.add(issue("session.cleanup-interval", "0보다 커야 합니다"));
            }
        }

        private void checkToken(List<Problem> problems) {
            if (clockSkew == null || clockSkew.isNegative() || clockSkew.compareTo(MAX_CLOCK_SKEW) > 0) {
                problems.add(issue("token.clock-skew", "0초에서 5분 사이여야 합니다"));
            }
            if (jwksMinRefetchInterval == null || jwksMinRefetchInterval.compareTo(MIN_JWKS_REFETCH_INTERVAL) < 0
                || jwksMinRefetchInterval.compareTo(MAX_JWKS_REFETCH_INTERVAL) > 0) {
                problems.add(issue("token.jwks-min-refetch-interval", "10초에서 1시간 사이여야 합니다"));
            }
            if (isBlank(requiredAudience)) {
                problems.add(issue("token.required-audience", "필수입니다 (스타터는 client id를 기본값으로 쓴다)"));
            }
        }

        private KeycloakKeyRing checkCrypto(List<Problem> problems) {
            int before = problems.size();
            if (keys.isEmpty()) {
                problems.add(issue("crypto.keys", "키가 하나도 없습니다. 32바이트 이상 난수를 base64로 넣으세요 (예: openssl rand -base64 32)"));
            }
            Map<String, byte[]> decoded = new LinkedHashMap<>();
            keys.forEach((id, value) -> {
                if (id == null || !KEY_ID.matcher(id).matches()) {
                    problems.add(issue("crypto.keys", "키 id는 영문·숫자·_·-만 32자까지 됩니다"));
                    return;
                }
                byte[] key = decode(value);
                if (key == null) {
                    problems.add(issue("crypto.keys." + id, "base64가 아닙니다"));
                } else if (key.length < KeycloakKeyRing.MIN_KEY_BYTES) {
                    problems.add(issue("crypto.keys." + id, KeycloakKeyRing.MIN_KEY_BYTES + "바이트보다 짧습니다 (" + key.length + "바이트)"));
                } else {
                    decoded.put(id, key);
                }
            });
            if (isBlank(activeKeyId)) {
                problems.add(issue("crypto.active-key-id", "필수입니다"));
            } else if (!keys.isEmpty() && !keys.containsKey(activeKeyId)) {
                problems.add(issue("crypto.active-key-id", "crypto.keys에 없는 키 id입니다: " + activeKeyId));
            }
            if (problems.size() > before) {
                return null;
            }
            return new KeycloakKeyRing(activeKeyId, decoded);
        }

        private static void checkPath(List<Problem> problems, String property, String path) {
            if (isBlank(path) || !path.startsWith("/") || path.startsWith("//") || path.contains("\\")) {
                problems.add(issue(property, "/로 시작하는 경로여야 합니다 (//와 \\는 안 됩니다)"));
            }
        }

        private static byte[] decode(String value) {
            if (value == null) {
                return null;
            }
            String trimmed = value.trim();
            try {
                return Base64.getDecoder().decode(trimmed);
            } catch (IllegalArgumentException standard) {
                try {
                    return Base64.getUrlDecoder().decode(trimmed);
                } catch (IllegalArgumentException urlSafe) {
                    return null;
                }
            }
        }

        private static Problem issue(String property, String message) {
            return new Problem(PREFIX + "." + property, message);
        }

        private static boolean isPositive(Duration duration) {
            return duration != null && !duration.isNegative() && !duration.isZero();
        }

        private static boolean isBlank(String value) {
            return value == null || value.isBlank();
        }
    }
}
