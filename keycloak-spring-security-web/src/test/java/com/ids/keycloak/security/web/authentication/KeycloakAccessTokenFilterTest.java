package com.ids.keycloak.security.web.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;

import com.ids.keycloak.security.authentication.DefaultKeycloakPrincipalConverter;
import com.ids.keycloak.security.authentication.KeycloakPrincipal;
import com.ids.keycloak.security.authentication.KeycloakPrincipalConverter;
import com.ids.keycloak.security.crypto.AesGcmTokenCipher;
import com.ids.keycloak.security.crypto.EncryptedToken;
import com.ids.keycloak.security.crypto.KeycloakKeyRing;
import com.ids.keycloak.security.event.KeycloakSessionEndReason;
import com.ids.keycloak.security.event.KeycloakSessionEvent;
import com.ids.keycloak.security.session.InMemoryKeycloakSessionStore;
import com.ids.keycloak.security.session.KeycloakSessionRecord;
import com.ids.keycloak.security.session.SessionIds;
import com.ids.keycloak.security.token.AccessTokenValidationResult;
import com.ids.keycloak.security.web.cookie.DefaultKeycloakCookieWriter;
import com.ids.keycloak.security.web.error.KeycloakErrorResponseWriter;
import com.ids.keycloak.security.web.logout.KeycloakLocalLogoutHandler;
import com.ids.keycloak.security.web.refresh.KeycloakRefreshResult;
import com.ids.keycloak.security.web.refresh.KeycloakRefreshService;

import jakarta.servlet.http.Cookie;

class KeycloakAccessTokenFilterTest {

    static final Instant NOW = Instant.parse("2026-11-10T03:00:00Z");

    final InMemoryKeycloakSessionStore store = new InMemoryKeycloakSessionStore();
    final DefaultKeycloakCookieWriter cookies = new DefaultKeycloakCookieWriter("demo");
    final List<KeycloakSessionEvent> events = new ArrayList<>();
    final List<String> validated = new ArrayList<>();
    AccessTokenValidationResult validation = AccessTokenValidationResult.valid(jwt());
    KeycloakPrincipalConverter converter = new DefaultKeycloakPrincipalConverter();

    /** 갱신 결과를 테스트가 정한다. 부른 sid를 적어 둔다. */
    final List<String> refreshedSids = new ArrayList<>();
    KeycloakRefreshResult refreshResult = KeycloakRefreshResult.refreshed(jwt("eyJ.new"), Duration.ofSeconds(60));

    KeycloakAccessTokenFilter filter() {
        KeycloakRefreshService refresh = new KeycloakRefreshService(store, new AesGcmTokenCipher(new KeycloakKeyRing("k1",
            Map.of("k1", "0123456789abcdef0123456789abcdef".getBytes()))), rt -> null, token -> validation, events::add,
            Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofSeconds(10)) {
            @Override
            public KeycloakRefreshResult refresh(String sid) {
                refreshedSids.add(sid);
                return refreshResult;
            }
        };
        return new KeycloakAccessTokenFilter(token -> {
            validated.add(token);
            return validation;
        }, accessToken -> converter.convert(accessToken), cookies,
            new KeycloakLocalLogoutHandler(store, cookies, events::add, Clock.fixed(NOW, ZoneOffset.UTC)),
            new KeycloakErrorResponseWriter("keycloak"), refresh, "X-Background");
    }

    static Jwt jwt() {
        return jwt("eyJ.at");
    }

    static Jwt jwt(String value) {
        return Jwt.withTokenValue(value).header("alg", "RS256").subject("user-1").claim("sid", "kc-sid-1").claim("azp", "demo")
            .issuedAt(NOW).expiresAt(NOW.plusSeconds(60)).build();
    }

    /** 체인 끝(컨트롤러 자리)에서 본 인증. */
    final AtomicReference<Authentication> seen = new AtomicReference<>();

    MockFilterChain chain() {
        return new MockFilterChain(new jakarta.servlet.http.HttpServlet() {
        }, (req, res, next) -> seen.set(SecurityContextHolder.getContext().getAuthentication()));
    }

    String sidWithRow() {
        String sid = SessionIds.newSid();
        store.insert(new KeycloakSessionRecord(UUID.randomUUID(), SessionIds.hash(sid), "user-1", "kc-sid-1",
            new EncryptedToken("k1", new byte[]{1, 2, 3}), NOW.plusSeconds(3600), NOW, NOW.plusSeconds(3600), null));
        return sid;
    }

    static MockHttpServletRequest request(Cookie... cookies) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/me");
        if (cookies.length > 0) {
            request.setCookies(cookies);
        }
        return request;
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("REQ-01 at 쿠키가 통과하면 KeycloakPrincipal(sub·sid·azp)이 체인 끝까지 간다. 쿠키를 새로 쓰지 않고 HttpSession도 없다")
    void validTokenAuthenticates() throws Exception {
        String sid = sidWithRow();
        MockHttpServletRequest request = request(new Cookie("__Host-demo_at", "eyJ.at"), new Cookie("__Host-demo_sid", sid));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter().doFilter(request, response, chain());

        assertThat(validated).containsExactly("eyJ.at");
        KeycloakPrincipal principal = (KeycloakPrincipal) seen.get().getPrincipal();
        assertThat(principal.subject()).isEqualTo("user-1");
        assertThat(principal.sessionId()).isEqualTo("kc-sid-1");
        assertThat(principal.authorizedParty()).isEqualTo("demo");
        assertThat(response.getHeaders("Set-Cookie")).isEmpty();
        assertThat(request.getSession(false)).as("HttpSession을 만들지 않는다").isNull();
        assertThat(new RequestAttributeSecurityContextRepository().loadDeferredContext(request).get().getAuthentication())
            .as("오류 디스패치에서도 보이도록 요청 속성에 둔다").isSameAs(seen.get());
        assertThat(store.snapshot()).hasSize(1);
    }

    @Test
    @DisplayName("REQ-02 쿠키가 하나도 없으면 로그인 안 한 채로 넘기고, 검증·갱신·로그아웃을 하지 않는다")
    void noCookiePassesThrough() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter().doFilter(request(), response, chain());

        assertThat(seen.get()).isNull();
        assertThat(validated).isEmpty();
        assertThat(refreshedSids).isEmpty();
        assertThat(response.getHeaders("Set-Cookie")).isEmpty();
    }

    @Test
    @DisplayName("REQ-04 서명이 틀리면(만료 말고 다른 실패) 세션 행·쿠키를 지우고 사유 invalid_token, 로그인 안 한 채로 넘긴다")
    void invalidTokenLogsOutLocally() throws Exception {
        String sid = sidWithRow();
        validation = AccessTokenValidationResult.invalid("서명이 맞지 않습니다");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter().doFilter(request(new Cookie("__Host-demo_at", "eyJ.bad"), new Cookie("__Host-demo_sid", sid)), response, chain());

        assertThat(seen.get()).isNull();
        assertThat(store.snapshot()).isEmpty();
        assertThat(response.getHeaders("Set-Cookie"))
            .anyMatch(c -> c.startsWith("__Host-demo_sid=;") && c.contains("Max-Age=0"))
            .anyMatch(c -> c.startsWith("__Host-demo_at=;") && c.contains("Max-Age=0"))
            .anyMatch(c -> c.startsWith("__Host-demo_csrf=;") && c.contains("Max-Age=0"));
        assertThat(events).singleElement().satisfies(e -> {
            assertThat(e.type()).isEqualTo(KeycloakSessionEvent.Type.ENDED);
            assertThat(e.endReason()).isEqualTo(KeycloakSessionEndReason.INVALID_TOKEN);
        });
    }

    @Test
    @DisplayName("REFRESH-01 만료면 sid로 갱신해 새 at 쿠키를 쓰고, 새 토큰의 사용자로 요청을 이어 간다")
    void expiredTokenIsRefreshed() throws Exception {
        String sid = sidWithRow();
        validation = AccessTokenValidationResult.expired("만료");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter().doFilter(request(new Cookie("__Host-demo_at", "eyJ.old"), new Cookie("__Host-demo_sid", sid)), response, chain());

        assertThat(refreshedSids).containsExactly(sid);
        assertThat(seen.get().getName()).isEqualTo("user-1");
        assertThat(((KeycloakPrincipal) seen.get().getPrincipal()).subject()).isEqualTo("user-1");
        assertThat(response.getHeaders("Set-Cookie")).singleElement()
            .satisfies(c -> assertThat(c).startsWith("__Host-demo_at=eyJ.new;").contains("Max-Age=60"));
        assertThat(events).isEmpty();
    }

    @Test
    @DisplayName("REFRESH-01 at 쿠키가 없고 sid만 있어도(브라우저가 at를 버림) 갱신한다")
    void missingAccessTokenIsRefreshed() throws Exception {
        String sid = sidWithRow();

        filter().doFilter(request(new Cookie("__Host-demo_sid", sid)), new MockHttpServletResponse(), chain());

        assertThat(validated).isEmpty();
        assertThat(refreshedSids).containsExactly(sid);
        assertThat(seen.get()).isNotNull();
    }

    @Test
    @DisplayName("REFRESH-07 X-Background 요청은 갱신하지 않고 로그인 안 한 채로 넘긴다. 세션은 그대로")
    void backgroundRequestDoesNotRefresh() throws Exception {
        String sid = sidWithRow();
        validation = AccessTokenValidationResult.expired("만료");
        MockHttpServletRequest request = request(new Cookie("__Host-demo_at", "eyJ.old"), new Cookie("__Host-demo_sid", sid));
        request.addHeader("X-Background", "1");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter().doFilter(request, response, chain());

        assertThat(refreshedSids).isEmpty();
        assertThat(seen.get()).isNull();
        assertThat(store.snapshot()).hasSize(1);
        assertThat(response.getHeaders("Set-Cookie")).isEmpty();
    }

    @Test
    @DisplayName("갱신 결과 세션이 끝났으면 쿠키를 모두 지우고 로그인 안 한 채로 넘긴다")
    void sessionEndedClearsCookies() throws Exception {
        String sid = sidWithRow();
        refreshResult = KeycloakRefreshResult.sessionEnded(KeycloakSessionEndReason.ABSOLUTE_TIMEOUT);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter().doFilter(request(new Cookie("__Host-demo_sid", sid)), response, chain());

        assertThat(seen.get()).isNull();
        assertThat(response.getHeaders("Set-Cookie")).hasSize(4).allMatch(c -> c.contains("Max-Age=0"));
    }

    @Test
    @DisplayName("REFRESH-06 갱신할 때 Keycloak을 부르지 못하면 503, 쿠키는 그대로")
    void refreshUnavailableIs503() throws Exception {
        String sid = sidWithRow();
        refreshResult = KeycloakRefreshResult.unavailable();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = chain();

        filter().doFilter(request(new Cookie("__Host-demo_sid", sid)), response, chain);

        assertThat(response.getStatus()).isEqualTo(503);
        assertThat(response.getHeaders("Set-Cookie")).isEmpty();
        assertThat(chain.getRequest()).isNull();
    }

    @Test
    @DisplayName("sid 쿠키가 없거나 sid 모양이 아니면 갱신하지 않는다")
    void noSidNoRefresh() throws Exception {
        filter().doFilter(request(new Cookie("__Host-demo_sid", "not-a-sid")), new MockHttpServletResponse(), chain());

        assertThat(refreshedSids).isEmpty();
        assertThat(seen.get()).isNull();
    }

    @Test
    @DisplayName("JWKS를 받지 못하면 로그아웃하지 않고 503 JSON")
    void jwksUnavailableIs503() throws Exception {
        String sid = sidWithRow();
        validation = AccessTokenValidationResult.unavailable("JWKS 연결 실패");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = chain();

        filter().doFilter(request(new Cookie("__Host-demo_at", "eyJ.at"), new Cookie("__Host-demo_sid", sid)), response, chain);

        assertThat(response.getStatus()).isEqualTo(503);
        assertThat(response.getContentAsString()).contains("\"code\":\"KEYCLOAK_UNAVAILABLE\"");
        assertThat(chain.getRequest()).as("체인을 더 진행하지 않는다").isNull();
        assertThat(store.snapshot()).hasSize(1);
    }

    @Test
    @DisplayName("REQ-06 바꿔 끼운 변환기가 만든 인증과 권한이 그대로 간다")
    void customConverter() throws Exception {
        converter = accessToken -> new TestingAuthenticationToken("app-user-" + accessToken.getSubject(), null, "ROLE_ADMIN");

        filter().doFilter(request(new Cookie("__Host-demo_at", "eyJ.at")), new MockHttpServletResponse(), chain());

        assertThat(seen.get().getPrincipal()).isEqualTo("app-user-user-1");
        assertThat(seen.get().getAuthorities()).extracting(Object::toString).containsExactly("ROLE_ADMIN");
    }

    @Test
    @DisplayName("변환기가 AuthenticationException을 던지면 그 요청만 로그인 안 한 것으로 보고 세션은 둔다")
    void converterRejects() throws Exception {
        String sid = sidWithRow();
        converter = accessToken -> {
            throw new BadCredentialsException("앱 사용자 없음");
        };

        filter().doFilter(request(new Cookie("__Host-demo_at", "eyJ.at"), new Cookie("__Host-demo_sid", sid)),
            new MockHttpServletResponse(), chain());

        assertThat(seen.get()).isNull();
        assertThat(store.snapshot()).hasSize(1);
    }

    @Test
    @DisplayName("앞에서 다른 방식으로 이미 인증했으면 건드리지 않는다")
    void keepsExistingAuthentication() throws Exception {
        TestingAuthenticationToken existing = new TestingAuthenticationToken("service", null, "ROLE_SERVICE");
        SecurityContextHolder.getContext().setAuthentication(existing);

        filter().doFilter(request(new Cookie("__Host-demo_at", "eyJ.at")), new MockHttpServletResponse(), chain());

        assertThat(seen.get()).isSameAs(existing);
        assertThat(validated).isEmpty();
    }
}
