package com.ids.keycloak.security.web.login;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.jwt.Jwt;

import com.ids.keycloak.security.crypto.AesGcmTokenCipher;
import com.ids.keycloak.security.crypto.KeycloakCsrfTokenSigner;
import com.ids.keycloak.security.crypto.KeycloakKeyRing;
import com.ids.keycloak.security.event.KeycloakSessionEndReason;
import com.ids.keycloak.security.event.KeycloakSessionEvent;
import com.ids.keycloak.security.session.InMemoryKeycloakSessionStore;
import com.ids.keycloak.security.session.KeycloakSessionRecord;
import com.ids.keycloak.security.session.SessionIds;
import com.ids.keycloak.security.token.AccessTokenValidationResult;
import com.ids.keycloak.security.token.KeycloakAccessTokenValidator;
import com.ids.keycloak.security.web.cookie.DefaultKeycloakCookieWriter;

import jakarta.servlet.http.Cookie;

class KeycloakLoginSuccessHandlerTest {

    static final Instant NOW = Instant.parse("2026-11-10T03:00:00Z");
    static final KeycloakKeyRing KEYS = new KeycloakKeyRing("k1", Map.of("k1", "0123456789abcdef0123456789abcdef".getBytes()));

    final InMemoryKeycloakSessionStore store = new InMemoryKeycloakSessionStore();
    final AesGcmTokenCipher cipher = new AesGcmTokenCipher(KEYS);
    final KeycloakCsrfTokenSigner csrf = new KeycloakCsrfTokenSigner(KEYS);
    final DefaultKeycloakCookieWriter cookies = new DefaultKeycloakCookieWriter("demo");
    final List<KeycloakSessionEvent> events = new ArrayList<>();
    AccessTokenValidationResult validation = AccessTokenValidationResult.valid(jwt("user-1", "kc-sid-1"));
    final KeycloakAccessTokenValidator validator = token -> validation;
    final KeycloakLoginSuccessHandler handler = new KeycloakLoginSuccessHandler(validator, store, cipher, csrf, cookies, events::add,
        new KeycloakLoginFailureHandler(URI.create("https://app.kss.test"), cookies), Clock.fixed(NOW, ZoneOffset.UTC),
        Duration.ofHours(12), URI.create("https://app.kss.test"));

    static Jwt jwt(String sub, String sid) {
        return Jwt.withTokenValue("eyJ.access.token").header("alg", "RS256").subject(sub).claim("sid", sid)
            .issuedAt(NOW).expiresAt(NOW.plusSeconds(60)).build();
    }

    static MockHttpServletRequest callback(OAuth2RefreshToken refreshToken, String returnPath) {
        ClientRegistration registration = ClientRegistration.withRegistrationId("keycloak").clientId("demo").clientSecret("s")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .authorizationUri("https://sso/auth").tokenUri("https://sso/token").build();
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "eyJ.access.token", NOW,
            NOW.plusSeconds(60));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login/oauth2/code/keycloak");
        request.setAttribute(KeycloakLoginAuthorizedClientRepository.ATTRIBUTE,
            new OAuth2AuthorizedClient(registration, "alice", accessToken, refreshToken));
        if (returnPath != null) {
            request.setAttribute(KeycloakAuthorizationRequestRepository.RETURN_PATH_ATTRIBUTE, returnPath);
        }
        return request;
    }

    static String cookieValue(MockHttpServletResponse response, String name) {
        return response.getHeaders("Set-Cookie").stream().filter(h -> h.startsWith(name + "="))
            .map(h -> h.substring(name.length() + 1, h.indexOf(';'))).findFirst().orElse(null);
    }

    @Test
    @DisplayName("LOGIN-03 세션 행 1개와 sid·at·csrf 쿠키를 만들고 화면 주소 + 돌아갈 경로로 302")
    void createsSession() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(callback(new OAuth2RefreshToken("refresh-token-1", NOW), "/items/3"), response, null);

        assertThat(response.getStatus()).isEqualTo(302);
        assertThat(response.getRedirectedUrl()).isEqualTo("https://app.kss.test/items/3");
        String sid = cookieValue(response, "__Host-demo_sid");
        assertThat(SessionIds.looksLikeSid(sid)).isTrue();
        assertThat(cookieValue(response, "__Host-demo_at")).isEqualTo("eyJ.access.token");
        assertThat(csrf.matches(sid, cookieValue(response, "__Host-demo_csrf"))).isTrue();
        assertThat(response.getHeaders("Set-Cookie")).filteredOn(h -> h.startsWith("__Host-demo_sid=")).first().asString().contains("Max-Age=43200");
        assertThat(response.getHeaders("Set-Cookie")).filteredOn(h -> h.startsWith("__Host-demo_at=")).first().asString().contains("Max-Age=60");

        KeycloakSessionRecord row = store.findBySidHash(SessionIds.hash(sid)).orElseThrow();
        assertThat(store.snapshot()).hasSize(1);
        assertThat(row.keycloakUserId()).isEqualTo("user-1");
        assertThat(row.kcSid()).isEqualTo("kc-sid-1");
        assertThat(cipher.decrypt(row.refreshToken())).isEqualTo("refresh-token-1");
        assertThat(row.absoluteExpiresAt()).isEqualTo(NOW.plus(Duration.ofHours(12)));
        assertThat(row.refreshExpiresAt()).as("JWT가 아닌 리프레시 토큰은 절대 상한").isEqualTo(row.absoluteExpiresAt());
        assertThat(events).extracting(KeycloakSessionEvent::type).containsExactly(KeycloakSessionEvent.Type.CREATED);
    }

    @Test
    @DisplayName("LOGIN-06 예전 sid 쿠키가 있으면 그 행을 지우고 새 sid를 준다")
    void replacesPreviousSession() throws Exception {
        String oldSid = SessionIds.newSid();
        KeycloakSessionRecord old = new KeycloakSessionRecord(UUID.randomUUID(), SessionIds.hash(oldSid), "user-1", "kc-old",
            cipher.encrypt("old-rt"), NOW.plusSeconds(600), NOW.minusSeconds(60), NOW.plusSeconds(3600), null);
        store.insert(old);
        MockHttpServletRequest request = callback(new OAuth2RefreshToken("refresh-token-2", NOW), "/");
        request.setCookies(new Cookie("__Host-demo_sid", oldSid));
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(request, response, null);

        assertThat(store.findBySidHash(old.sidHash())).isEmpty();
        assertThat(cookieValue(response, "__Host-demo_sid")).isNotEqualTo(oldSid);
        assertThat(store.snapshot()).hasSize(1);
        assertThat(events).extracting(KeycloakSessionEvent::type)
            .containsExactly(KeycloakSessionEvent.Type.ENDED, KeycloakSessionEvent.Type.CREATED);
        assertThat(events.get(0).endReason()).isEqualTo(KeycloakSessionEndReason.RELOGIN);
    }

    @Test
    @DisplayName("액세스 토큰이 검증 규칙에 맞지 않거나 sid가 없으면 세션 행 없이 ?login_error=invalid_token")
    void invalidToken() throws Exception {
        validation = AccessTokenValidationResult.invalid("aud");
        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.onAuthenticationSuccess(callback(new OAuth2RefreshToken("rt", NOW), "/"), response, null);
        assertThat(response.getRedirectedUrl()).isEqualTo("https://app.kss.test/?login_error=invalid_token");

        validation = AccessTokenValidationResult.valid(jwt("user-1", null));
        MockHttpServletResponse noSid = new MockHttpServletResponse();
        handler.onAuthenticationSuccess(callback(new OAuth2RefreshToken("rt", NOW), "/"), noSid, null);
        assertThat(noSid.getRedirectedUrl()).isEqualTo("https://app.kss.test/?login_error=invalid_token");

        assertThat(store.snapshot()).isEmpty();
        assertThat(cookieValue(response, "__Host-demo_sid")).isNull();
    }

    @Test
    @DisplayName("리프레시 토큰이 없으면 세션 행 없이 ?login_error=login_failed")
    void noRefreshToken() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.onAuthenticationSuccess(callback(null, "/"), response, null);
        assertThat(response.getRedirectedUrl()).isEqualTo("https://app.kss.test/?login_error=login_failed");
        assertThat(store.snapshot()).isEmpty();
    }
}
