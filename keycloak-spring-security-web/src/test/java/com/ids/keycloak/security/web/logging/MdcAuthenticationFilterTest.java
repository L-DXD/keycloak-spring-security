package com.ids.keycloak.security.web.logging;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.jwt.Jwt;

import com.ids.keycloak.security.authentication.KeycloakAuthenticationToken;
import com.ids.keycloak.security.authentication.KeycloakPrincipal;
import com.ids.keycloak.security.config.KeycloakLoggingSettings;
import com.ids.keycloak.security.logging.DefaultPiiMaskingSanitizer;
import com.ids.keycloak.security.logging.LoggingContextKeys;
import com.ids.keycloak.security.logging.NoOpLoggingValueSanitizer;

/** EVT-03: 사용자 MDC 키 (v2 키 이름 그대로). v2의 이 테스트는 주석 처리돼 있어 v3에서 새로 짰다. */
class MdcAuthenticationFilterTest {

    private static final Instant NOW = Instant.parse("2026-11-10T03:00:00Z");

    private final WebMdcContextAccessor accessor = new WebMdcContextAccessor();

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        accessor.clear();
        MDC.clear();
    }

    private Map<String, String> run(Authentication authentication, KeycloakLoggingSettings settings, boolean mask) throws Exception {
        SecurityContextHolder.setContext(new SecurityContextImpl(authentication));
        Map<String, String> seen = new HashMap<>();
        new MdcAuthenticationFilter(accessor, settings, mask ? new DefaultPiiMaskingSanitizer() : new NoOpLoggingValueSanitizer())
            .doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), (req, res) -> {
                Map<String, String> copy = MDC.getCopyOfContextMap();
                if (copy != null) {
                    seen.putAll(copy);
                }
            });
        return seen;
    }

    private static Jwt jwt(String username) {
        Jwt.Builder builder = Jwt.withTokenValue("eyJ.a.b").header("alg", "RS256").subject("user-1").claim("sid", "kc-sid-1")
            .claim("azp", "demo").issuedAt(NOW).expiresAt(NOW.plusSeconds(60));
        if (username != null) {
            builder.claim("preferred_username", username);
        }
        return builder.build();
    }

    private static KeycloakAuthenticationToken keycloak(String username) {
        Jwt jwt = jwt(username);
        return new KeycloakAuthenticationToken(KeycloakPrincipal.from(jwt), jwt, List.of());
    }

    @Test
    @DisplayName("KeycloakPrincipal: userId=sub, username=preferred_username, sessionId=Keycloak sid")
    void keycloakPrincipal() throws Exception {
        assertThat(run(keycloak("alice"), KeycloakLoggingSettings.defaults(), true))
            .containsEntry(LoggingContextKeys.USER_ID, "user-1")
            .containsEntry(LoggingContextKeys.USERNAME, "alice")
            .containsEntry(LoggingContextKeys.SESSION_ID, "kc-sid-1");
    }

    @Test
    @DisplayName("(v3) username이 이메일이면 가리기를 거친다. 가리지 않는 sanitizer면 그대로")
    void usernameMasked() throws Exception {
        assertThat(run(keycloak("alice@example.com"), KeycloakLoggingSettings.defaults(), true))
            .containsEntry(LoggingContextKeys.USERNAME, "a***@example.com");
        assertThat(run(keycloak("alice@example.com"), KeycloakLoggingSettings.defaults(), false))
            .containsEntry(LoggingContextKeys.USERNAME, "alice@example.com");
    }

    @Test
    @DisplayName("끈 키는 넣지 않는다")
    void off() throws Exception {
        KeycloakLoggingSettings settings = KeycloakLoggingSettings.builder()
            .includeUserId(false).includeUsername(false).includeSessionId(false).build();
        assertThat(run(keycloak("alice"), settings, true))
            .doesNotContainKeys(LoggingContextKeys.USER_ID, LoggingContextKeys.USERNAME, LoggingContextKeys.SESSION_ID);
    }

    @Test
    @DisplayName("preferred_username이 없으면 username을 넣지 않는다")
    void noUsername() throws Exception {
        assertThat(run(keycloak(null), KeycloakLoggingSettings.defaults(), true))
            .containsEntry(LoggingContextKeys.USER_ID, "user-1").doesNotContainKey(LoggingContextKeys.USERNAME);
    }

    @Test
    @DisplayName("익명·로그인 안 함은 넣지 않는다")
    void anonymous() throws Exception {
        Authentication anonymous = new AnonymousAuthenticationToken("key", "anonymousUser",
            AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
        assertThat(run(anonymous, KeycloakLoggingSettings.defaults(), true)).isEmpty();
        assertThat(run(null, KeycloakLoggingSettings.defaults(), true)).isEmpty();
    }

    @Test
    @DisplayName("OidcUser·Jwt 주체도 같은 키로 넣는다 (사용자 체인이 다른 인증을 섞어 쓸 때)")
    void otherPrincipals() throws Exception {
        OidcIdToken idToken = new OidcIdToken("id", NOW, NOW.plusSeconds(60),
            Map.of("sub", "user-2", "sid", "kc-sid-2", "preferred_username", "bob"));
        Authentication oidc = new TestingAuthenticationToken(new DefaultOidcUser(List.of(), idToken), null, "ROLE_USER");
        assertThat(run(oidc, KeycloakLoggingSettings.defaults(), true))
            .containsEntry(LoggingContextKeys.USER_ID, "user-2").containsEntry(LoggingContextKeys.USERNAME, "bob")
            .containsEntry(LoggingContextKeys.SESSION_ID, "kc-sid-2");

        Authentication jwt = new TestingAuthenticationToken(jwt("carol"), null, "ROLE_USER");
        assertThat(run(jwt, KeycloakLoggingSettings.defaults(), true))
            .containsEntry(LoggingContextKeys.USER_ID, "user-1").containsEntry(LoggingContextKeys.USERNAME, "carol");
    }

    @Test
    @DisplayName("모르는 주체는 이름만 username으로")
    void unknownPrincipal() throws Exception {
        assertThat(run(new TestingAuthenticationToken("dave", null, "ROLE_USER"), KeycloakLoggingSettings.defaults(), true))
            .containsEntry(LoggingContextKeys.USERNAME, "dave").doesNotContainKeys(LoggingContextKeys.USER_ID, LoggingContextKeys.SESSION_ID);
    }
}
