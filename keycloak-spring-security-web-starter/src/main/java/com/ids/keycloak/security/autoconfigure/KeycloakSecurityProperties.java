package com.ids.keycloak.security.autoconfigure;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;

import com.ids.keycloak.security.config.KeycloakSecuritySettings;
import com.ids.keycloak.security.config.SessionStoreType;

/**
 * {@code keycloak.security.*} 설정. 기동 때 {@link KeycloakSecuritySettings}로 바꾸며 검사한다.
 * <p>
 * 필수: {@code frontend.base-url}, {@code crypto.active-key-id}, {@code crypto.keys}.
 * 그리고 Spring 설정 {@code spring.security.oauth2.client.registration.keycloak}(issuer, client id/secret).
 */
@ConfigurationProperties(prefix = KeycloakSecuritySettings.PREFIX)
public class KeycloakSecurityProperties {

    /** 라이브러리를 켜는가. 끄면 자동 설정이 아무 것도 올리지 않는다. */
    private boolean enabled = true;

    /** Spring OAuth2 Client 등록 id. */
    private String registrationId = "keycloak";

    private final Frontend frontend = new Frontend();
    private final Cookie cookie = new Cookie();
    private final Session session = new Session();
    private final Token token = new Token();
    private final Request request = new Request();
    private final Csrf csrf = new Csrf();
    private final Logout logout = new Logout();
    private final Crypto crypto = new Crypto();

    /** 로그인 없이 허용하는 경로 (예: /api/public/**). */
    private List<String> permitAllPaths = new ArrayList<>();

    /**
     * 검사를 마친 설정으로 바꾼다.
     *
     * @param clientId OAuth2 등록의 client id. 앱 이름과 aud 기본값으로 쓴다. 등록이 없으면 {@code null}
     */
    public KeycloakSecuritySettings.Builder toSettingsBuilder(String clientId) {
        return KeycloakSecuritySettings.builder()
            .registrationId(registrationId)
            .frontendBaseUrl(frontend.baseUrl)
            .logoutSuccessPath(frontend.logoutSuccessPath)
            .cookieAppName(cookie.appName != null ? cookie.appName : clientId)
            .sessionStore(session.store)
            .sessionTableName(session.tableName)
            .absoluteTimeout(session.absoluteTimeout)
            .refreshReuseWindow(session.refreshReuseWindow)
            .cleanupInterval(session.cleanupInterval)
            .clockSkew(token.clockSkew)
            .requiredAudience(token.requiredAudience != null ? token.requiredAudience : clientId)
            .backgroundHeader(request.backgroundHeader)
            .csrfEndpoint(csrf.endpoint)
            .revokeRefreshTokenOnLocalLogout(logout.revokeRefreshTokenOnLocalLogout)
            .permitAllPaths(permitAllPaths)
            .activeKeyId(crypto.activeKeyId)
            .keys(crypto.keys);
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getRegistrationId() {
        return registrationId;
    }

    public void setRegistrationId(String registrationId) {
        this.registrationId = registrationId;
    }

    public Frontend getFrontend() {
        return frontend;
    }

    public Cookie getCookie() {
        return cookie;
    }

    public Session getSession() {
        return session;
    }

    public Token getToken() {
        return token;
    }

    public Request getRequest() {
        return request;
    }

    public Csrf getCsrf() {
        return csrf;
    }

    public Logout getLogout() {
        return logout;
    }

    public Crypto getCrypto() {
        return crypto;
    }

    public List<String> getPermitAllPaths() {
        return permitAllPaths;
    }

    public void setPermitAllPaths(List<String> permitAllPaths) {
        this.permitAllPaths = permitAllPaths;
    }

    /** 화면. */
    public static class Frontend {

        /** 화면 주소 (필수). CORS·Origin 확인, 로그인 뒤·로그아웃 뒤 주소에 쓴다. https만 (http는 localhost만). */
        private String baseUrl;

        /** 로그아웃 뒤 화면 경로. */
        private String logoutSuccessPath = "/";

        public String getBaseUrl() {
            return baseUrl;
        }

        public void setBaseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
        }

        public String getLogoutSuccessPath() {
            return logoutSuccessPath;
        }

        public void setLogoutSuccessPath(String logoutSuccessPath) {
            this.logoutSuccessPath = logoutSuccessPath;
        }
    }

    /** 쿠키. */
    public static class Cookie {

        /** 쿠키 이름에 넣는 앱 이름 (__Host-{앱 이름}_sid). 없으면 client id. */
        private String appName;

        public String getAppName() {
            return appName;
        }

        public void setAppName(String appName) {
            this.appName = appName;
        }
    }

    /** 세션 행. */
    public static class Session {

        /** 세션 저장소. memory는 서버 한 대짜리 개발용. */
        private SessionStoreType store = SessionStoreType.JDBC;

        /** 세션 테이블 이름. */
        private String tableName = "auth_session";

        /** 로그인부터 이 시간이 지나면 다시 로그인시킨다. */
        private Duration absoluteTimeout = Duration.ofHours(12);

        /** 동시에 들어온 갱신 요청을 "방금 갱신함"으로 볼 시간. */
        private Duration refreshReuseWindow = Duration.ofSeconds(10);

        /** 끝난 세션 행을 지우는 주기. */
        private Duration cleanupInterval = Duration.ofMinutes(10);

        public SessionStoreType getStore() {
            return store;
        }

        public void setStore(SessionStoreType store) {
            this.store = store;
        }

        public String getTableName() {
            return tableName;
        }

        public void setTableName(String tableName) {
            this.tableName = tableName;
        }

        public Duration getAbsoluteTimeout() {
            return absoluteTimeout;
        }

        public void setAbsoluteTimeout(Duration absoluteTimeout) {
            this.absoluteTimeout = absoluteTimeout;
        }

        public Duration getRefreshReuseWindow() {
            return refreshReuseWindow;
        }

        public void setRefreshReuseWindow(Duration refreshReuseWindow) {
            this.refreshReuseWindow = refreshReuseWindow;
        }

        public Duration getCleanupInterval() {
            return cleanupInterval;
        }

        public void setCleanupInterval(Duration cleanupInterval) {
            this.cleanupInterval = cleanupInterval;
        }
    }

    /** 액세스 토큰 검증. */
    public static class Token {

        /** 시간 검사 오차 (0~5분). */
        private Duration clockSkew = Duration.ofSeconds(30);

        /** aud에 있어야 하는 값. 없으면 client id. */
        private String requiredAudience;

        public Duration getClockSkew() {
            return clockSkew;
        }

        public void setClockSkew(Duration clockSkew) {
            this.clockSkew = clockSkew;
        }

        public String getRequiredAudience() {
            return requiredAudience;
        }

        public void setRequiredAudience(String requiredAudience) {
            this.requiredAudience = requiredAudience;
        }
    }

    /** 요청. */
    public static class Request {

        /** 이 헤더가 붙은 요청은 토큰을 갱신하지 않는다 (화면의 자동 새로고침 등). */
        private String backgroundHeader = "X-Background";

        public String getBackgroundHeader() {
            return backgroundHeader;
        }

        public void setBackgroundHeader(String backgroundHeader) {
            this.backgroundHeader = backgroundHeader;
        }
    }

    /** CSRF. */
    public static class Csrf {

        /** CSRF 토큰을 주는 주소. */
        private String endpoint = "/api/csrf";

        public String getEndpoint() {
            return endpoint;
        }

        public void setEndpoint(String endpoint) {
            this.endpoint = endpoint;
        }
    }

    /** 로그아웃. */
    public static class Logout {

        /** 로컬 로그아웃(잘못된 토큰 등) 때 Keycloak 리프레시 토큰도 폐기한다. */
        private boolean revokeRefreshTokenOnLocalLogout = false;

        public boolean isRevokeRefreshTokenOnLocalLogout() {
            return revokeRefreshTokenOnLocalLogout;
        }

        public void setRevokeRefreshTokenOnLocalLogout(boolean revokeRefreshTokenOnLocalLogout) {
            this.revokeRefreshTokenOnLocalLogout = revokeRefreshTokenOnLocalLogout;
        }
    }

    /** 키. 값은 환경 변수나 비밀 저장소에서 넣는다. */
    public static class Crypto {

        /** 새로 암호화할 때 쓰는 키 id (필수). */
        private String activeKeyId;

        /** 키 id → base64 키 (32바이트 이상, 필수). 예: openssl rand -base64 32 */
        private Map<String, String> keys = new LinkedHashMap<>();

        public String getActiveKeyId() {
            return activeKeyId;
        }

        public void setActiveKeyId(String activeKeyId) {
            this.activeKeyId = activeKeyId;
        }

        public Map<String, String> getKeys() {
            return keys;
        }

        public void setKeys(Map<String, String> keys) {
            this.keys = keys;
        }
    }
}
