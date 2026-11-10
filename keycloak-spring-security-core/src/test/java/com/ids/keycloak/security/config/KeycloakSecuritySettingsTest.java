package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.ids.keycloak.security.config.KeycloakSecurityConfigurationException.Problem;

class KeycloakSecuritySettingsTest {

    static final String KEY_32 = Base64.getEncoder().encodeToString(new byte[32]);

    static KeycloakSecuritySettings.Builder valid() {
        return KeycloakSecuritySettings.builder()
            .frontendBaseUrl("https://app.example.com")
            .cookieAppName("demo")
            .requiredAudience("demo")
            .activeKeyId("k1")
            .keys(Map.of("k1", KEY_32));
    }

    static List<String> problemProperties(KeycloakSecuritySettings.Builder builder) {
        try {
            builder.build();
        } catch (KeycloakSecurityConfigurationException e) {
            return e.getProblems().stream().map(Problem::property).toList();
        }
        throw new AssertionError("기동 실패를 기대했다");
    }

    @Test
    @DisplayName("필수 값만 넣으면 기본값으로 채워진다 (01 설계 6절)")
    void defaults() {
        KeycloakSecuritySettings settings = valid().build();

        assertThat(settings.registrationId()).isEqualTo("keycloak");
        assertThat(settings.frontendOrigin()).isEqualTo("https://app.example.com");
        assertThat(settings.logoutSuccessPath()).isEqualTo("/");
        assertThat(settings.sessionStore()).isEqualTo(SessionStoreType.JDBC);
        assertThat(settings.sessionTableName()).isEqualTo("auth_session");
        assertThat(settings.absoluteTimeout()).isEqualTo(Duration.ofHours(12));
        assertThat(settings.refreshReuseWindow()).isEqualTo(Duration.ofSeconds(10));
        assertThat(settings.cleanupInterval()).isEqualTo(Duration.ofMinutes(10));
        assertThat(settings.clockSkew()).isEqualTo(Duration.ofSeconds(30));
        assertThat(settings.backgroundHeader()).isEqualTo("X-Background");
        assertThat(settings.csrfEndpoint()).isEqualTo("/api/csrf");
        assertThat(settings.revokeRefreshTokenOnLocalLogout()).isFalse();
        assertThat(settings.permitAllPaths()).isEmpty();
        assertThat(settings.keyRing().activeKeyId()).isEqualTo("k1");
        assertThat(settings.logging()).isEqualTo(KeycloakLoggingSettings.defaults());
        assertThat(settings.trustedProxyCount()).isZero();
    }

    @Test
    @DisplayName("toString에 키 값이 나오지 않는다")
    void toStringHasNoSecrets() {
        String key = Base64.getEncoder().encodeToString("0123456789abcdef0123456789abcdef".getBytes());
        KeycloakSecuritySettings settings = valid().keys(Map.of("k1", key)).build();

        assertThat(settings.toString()).doesNotContain(key).contains("activeKey=k1");
        assertThat(settings.keyRing().toString()).doesNotContain(key);
    }

    @Nested
    @DisplayName("frontend.base-url")
    class FrontendBaseUrl {

        @Test
        @DisplayName("CONF-02 없으면 설정 이름을 알려 주고 실패한다")
        void missing() {
            assertThat(problemProperties(valid().frontendBaseUrl(null)))
                .containsExactly("keycloak.security.frontend.base-url");
        }

        @ParameterizedTest
        @ValueSource(strings = {"http://app.example.com", "ftp://app.example.com", "app.example.com", "/relative"})
        @DisplayName("CONF-04 https가 아니고 localhost도 아니면 실패한다")
        void mustBeHttpsUnlessLoopback(String url) {
            assertThat(problemProperties(valid().frontendBaseUrl(url)))
                .containsExactly("keycloak.security.frontend.base-url");
        }

        @ParameterizedTest
        @ValueSource(strings = {"http://localhost:3000", "http://127.0.0.1:5173", "http://[::1]:8080", "https://app.example.com:8443/portal"})
        @DisplayName("CONF-04 http는 localhost·127.0.0.1·::1에서만 허용한다")
        void loopbackHttpIsAllowed(String url) {
            assertThat(valid().frontendBaseUrl(url).build().frontendBaseUrl().toString()).isEqualTo(url);
        }

        @Test
        @DisplayName("origin은 scheme·host·port만 남긴다")
        void originDropsPath() {
            assertThat(valid().frontendBaseUrl("https://App.Example.com:8443/portal").build().frontendOrigin())
                .isEqualTo("https://app.example.com:8443");
        }

        @ParameterizedTest
        @ValueSource(strings = {"https://user@app.example.com", "https://app.example.com?x=1", "https://app.example.com/#x"})
        @DisplayName("사용자 정보·쿼리·조각은 안 된다")
        void noUserInfoQueryOrFragment(String url) {
            assertThat(problemProperties(valid().frontendBaseUrl(url))).containsExactly("keycloak.security.frontend.base-url");
        }
    }

    @Nested
    @DisplayName("crypto")
    class Crypto {

        @Test
        @DisplayName("CONF-03 키가 없으면 실패한다")
        void noKeys() {
            assertThat(problemProperties(valid().keys(Map.of()))).contains("keycloak.security.crypto.keys");
        }

        @Test
        @DisplayName("CONF-03 32바이트보다 짧으면 실패하고, 메시지에 키 값이 없다")
        void shortKey() {
            String shortKey = Base64.getEncoder().encodeToString(new byte[31]);

            assertThatThrownBy(() -> valid().keys(Map.of("k1", shortKey)).build())
                .isInstanceOf(KeycloakSecurityConfigurationException.class)
                .hasMessageContaining("keycloak.security.crypto.keys.k1")
                .hasMessageContaining("31바이트")
                .hasMessageNotContaining(shortKey);
        }

        @Test
        @DisplayName("CONF-03 base64가 아니면 실패한다")
        void notBase64() {
            assertThat(problemProperties(valid().keys(Map.of("k1", "not base64 !!")))).containsExactly("keycloak.security.crypto.keys.k1");
        }

        @Test
        @DisplayName("CONF-03 활성 키 id가 없거나 키 묶음에 없으면 실패한다")
        void activeKeyId() {
            assertThat(problemProperties(valid().activeKeyId(null))).containsExactly("keycloak.security.crypto.active-key-id");
            assertThat(problemProperties(valid().activeKeyId("k9"))).containsExactly("keycloak.security.crypto.active-key-id");
        }

        @Test
        @DisplayName("URL 안전 base64도 받고, 키를 여러 개 둘 수 있다")
        void urlSafeAndMultipleKeys() {
            String urlSafe = Base64.getUrlEncoder().encodeToString(new byte[]{-1, -2, -3, -4, -5, -6, -7, -8, -9, -10, -11, -12, -13, -14, -15, -16,
                -17, -18, -19, -20, -21, -22, -23, -24, -25, -26, -27, -28, -29, -30, -31, -32});

            KeycloakSecuritySettings settings = valid().activeKeyId("k2").keys(Map.of("k1", KEY_32, "k2", urlSafe)).build();

            assertThat(settings.keyRing().keyIds()).containsExactlyInAnyOrder("k1", "k2");
            assertThat(settings.keyRing().activeKey()).hasSize(32);
        }
    }

    @Test
    @DisplayName("잘못된 것을 한 번에 모두 알려 준다")
    void reportsAllProblems() {
        List<String> properties = problemProperties(KeycloakSecuritySettings.builder()
            .cookieAppName("my.app")
            .sessionTableName("auth_session; drop table x")
            .absoluteTimeout(Duration.ZERO)
            .clockSkew(Duration.ofMinutes(10))
            .backgroundHeader("X Background")
            .csrfEndpoint("api/csrf")
            .permitAllPaths(List.of("/ok", "//evil"))
            .problem("spring.security.oauth2.client.registration.keycloak", "없습니다"));

        assertThat(properties).contains(
            "spring.security.oauth2.client.registration.keycloak",
            "keycloak.security.frontend.base-url",
            "keycloak.security.cookie.app-name",
            "keycloak.security.session.table-name",
            "keycloak.security.session.absolute-timeout",
            "keycloak.security.token.clock-skew",
            "keycloak.security.token.required-audience",
            "keycloak.security.request.background-header",
            "keycloak.security.csrf.endpoint",
            "keycloak.security.permit-all-paths[1]",
            "keycloak.security.crypto.keys",
            "keycloak.security.crypto.active-key-id");
    }

    @Test
    @DisplayName("refresh-reuse-window는 absolute-timeout보다 짧아야 한다")
    void reuseWindowShorterThanAbsoluteTimeout() {
        assertThat(problemProperties(valid().absoluteTimeout(Duration.ofSeconds(5)).refreshReuseWindow(Duration.ofSeconds(10))))
            .containsExactly("keycloak.security.session.refresh-reuse-window");
    }

    @Test
    @DisplayName("EVT-03 MDC 로깅 기본값은 v2와 같다")
    void loggingDefaultsMatchV2() {
        KeycloakLoggingSettings logging = KeycloakLoggingSettings.defaults();
        assertThat(logging.includeTraceId()).isTrue();
        assertThat(logging.includeHttpMethod()).isTrue();
        assertThat(logging.includeRequestUri()).isTrue();
        assertThat(logging.includeQueryString()).isFalse();
        assertThat(logging.includeClientIp()).isTrue();
        assertThat(logging.includeUserAgent()).isTrue();
        assertThat(logging.maxQueryLength()).isEqualTo(512);
        assertThat(logging.maxUserAgentLength()).isEqualTo(256);
        assertThat(logging.returnTraceIdHeader()).isTrue();
        assertThat(logging.includeResponseMetrics()).isFalse();
        assertThat(logging.excludePatterns()).containsExactly("/actuator/**");
        assertThat(logging.includeUserId()).isTrue();
        assertThat(logging.includeUsername()).isTrue();
        assertThat(logging.includeSessionId()).isTrue();
    }

    @Test
    @DisplayName("MDC 로깅 설정이 틀리면 설정 이름을 알려 주고 실패한다")
    void loggingProblems() {
        KeycloakLoggingSettings bad = KeycloakLoggingSettings.builder().maxQueryLength(0).maxUserAgentLength(KeycloakLoggingSettings.MAX_LENGTH + 1)
            .excludePatterns(List.of("/actuator/**", "health")).build();
        assertThat(problemProperties(valid().logging(bad).trustedProxyCount(-2))).containsExactlyInAnyOrder(
            "keycloak.security.trusted-proxy-count",
            "keycloak.security.logging.max-query-length",
            "keycloak.security.logging.max-user-agent-length",
            "keycloak.security.logging.exclude-patterns[1]");
        assertThat(valid().trustedProxyCount(-1).build().trustedProxyCount()).as("-1은 v2 호환으로 받는다").isEqualTo(-1);
    }
}
