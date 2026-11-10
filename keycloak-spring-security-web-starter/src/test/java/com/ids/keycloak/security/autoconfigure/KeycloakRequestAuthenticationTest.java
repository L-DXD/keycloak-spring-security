package com.ids.keycloak.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.Principal;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.FilterChainProxy;

import com.ids.keycloak.security.authentication.KeycloakPrincipal;
import com.ids.keycloak.security.authentication.KeycloakPrincipalConverter;
import com.ids.keycloak.security.config.KeycloakSecuritySettings;
import com.ids.keycloak.security.logging.LoggingContextAccessor;
import com.ids.keycloak.security.token.AccessTokenValidationResult;
import com.ids.keycloak.security.token.KeycloakAccessTokenValidator;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

/**
 * V3-08 요청 인증을 자동 설정의 기본 보안 체인 그대로 돌려 본다 (REQ-01·02·06, 통합).
 * 토큰 검증기만 테스트용으로 바꾼다 (서명 검증은 #80 단위·E2E 테스트가 본다).
 */
class KeycloakRequestAuthenticationTest {

    static final Instant NOW = Instant.now();

    static Jwt jwt() {
        return Jwt.withTokenValue("eyJ.at").header("alg", "RS256").subject("user-1").claim("sid", "kc-sid-1").claim("azp", "demo")
            .issuedAt(NOW).expiresAt(NOW.plusSeconds(60)).build();
    }

    final WebApplicationContextRunner runner = KeycloakSecurityAutoConfigurationTest
        .runnerWith(KeycloakSecurityAutoConfigurationTest.registration(KeycloakSecurityAutoConfigurationTest.ISSUER))
        .withPropertyValues("keycloak.security.permit-all-paths=/api/public/**")
        .withBean(KeycloakAccessTokenValidator.class, () -> token -> "eyJ.at".equals(token)
            ? AccessTokenValidationResult.valid(jwt()) : AccessTokenValidationResult.invalid("서명이 맞지 않습니다"));

    /** 기본 체인으로 요청 하나를 보내고, 체인 끝(컨트롤러 자리)에서 본 사용자를 돌려준다. */
    static Principal send(FilterChainProxy chain, MockHttpServletRequest request, MockHttpServletResponse response) throws Exception {
        AtomicReference<Principal> seen = new AtomicReference<>();
        chain.doFilter(request, response, (req, res) -> seen.set(((HttpServletRequest) req).getUserPrincipal()));
        return seen.get();
    }

    static MockHttpServletRequest get(String path, Cookie... cookies) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        if (cookies.length > 0) {
            request.setCookies(cookies);
        }
        return request;
    }

    @Test
    @DisplayName("REQ-01 (통합) at 쿠키가 통과하면 컨트롤러에 KeycloakPrincipal이 들어온다")
    void authenticatedRequest() {
        runner.run(context -> {
            FilterChainProxy chain = context.getBean("springSecurityFilterChain", FilterChainProxy.class);
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockHttpServletRequest request = get("/api/me", new Cookie("__Host-demo_at", "eyJ.at"));

            Principal principal = send(chain, request, response);

            assertThat(response.getStatus()).isEqualTo(200);
            assertThat(principal).isInstanceOf(Authentication.class);
            assertThat(principal.getName()).isEqualTo("user-1");
            assertThat(((Authentication) principal).getPrincipal()).isInstanceOfSatisfying(KeycloakPrincipal.class,
                p -> assertThat(p.sessionId()).isEqualTo("kc-sid-1"));
            assertThat(response.getHeaders("Set-Cookie")).isEmpty();
            assertThat(request.getSession(false)).as("REQ-05 HttpSession을 만들지 않는다").isNull();
        });
    }

    @Test
    @DisplayName("REQ-01·02 (통합) 쿠키가 없으면 로그인 필요 경로는 401 JSON, permit-all 경로는 통과")
    void unauthenticatedRequests() {
        runner.run(context -> {
            FilterChainProxy chain = context.getBean("springSecurityFilterChain", FilterChainProxy.class);

            MockHttpServletResponse protectedResponse = new MockHttpServletResponse();
            assertThat(send(chain, get("/api/me"), protectedResponse)).isNull();
            assertThat(protectedResponse.getStatus()).isEqualTo(401);
            assertThat(protectedResponse.getContentAsString()).contains("\"code\":\"AUTHENTICATION_REQUIRED\"",
                "\"loginUrl\":\"/oauth2/authorization/keycloak\"");

            MockHttpServletResponse publicResponse = new MockHttpServletResponse();
            send(chain, get("/api/public/ping"), publicResponse);
            assertThat(publicResponse.getStatus()).isEqualTo(200);
        });
    }

    @Test
    @DisplayName("REQ-04 (통합) 서명이 틀린 at 쿠키는 401이고 쿠키 4개를 지운다")
    void invalidTokenIs401AndClearsCookies() {
        runner.run(context -> {
            FilterChainProxy chain = context.getBean("springSecurityFilterChain", FilterChainProxy.class);
            MockHttpServletResponse response = new MockHttpServletResponse();

            send(chain, get("/api/me", new Cookie("__Host-demo_at", "eyJ.tampered")), response);

            assertThat(response.getStatus()).isEqualTo(401);
            assertThat(response.getHeaders("Set-Cookie")).hasSize(4).allMatch(c -> c.contains("Max-Age=0"));
        });
    }

    @Test
    @DisplayName("REQ-06 (통합) 사용자 KeycloakPrincipalConverter 빈이 만든 principal과 권한이 컨트롤러에 들어온다")
    void customPrincipalConverter() {
        record AppUser(String id, String department) {
        }
        runner.withBean(KeycloakPrincipalConverter.class, () -> accessToken -> UsernamePasswordAuthenticationToken.authenticated(
                new AppUser(accessToken.getSubject(), "dev"), null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))))
            .run(context -> {
                FilterChainProxy chain = context.getBean("springSecurityFilterChain", FilterChainProxy.class);

                Principal principal = send(chain, get("/api/me", new Cookie("__Host-demo_at", "eyJ.at")), new MockHttpServletResponse());

                Authentication authentication = (Authentication) principal;
                assertThat(authentication.getPrincipal()).isEqualTo(new AppUser("user-1", "dev"));
                assertThat(authentication.getAuthorities()).extracting(Object::toString).containsExactly("ROLE_ADMIN");
            });
    }

    /** 체인 끝(컨트롤러 자리)에서 MDC를 떠서 돌려준다. */
    static Map<String, String> sendAndCaptureMdc(FilterChainProxy chain, MockHttpServletRequest request, MockHttpServletResponse response)
        throws Exception {
        Map<String, String> seen = new HashMap<>();
        chain.doFilter(request, response, (req, res) -> {
            Map<String, String> copy = MDC.getCopyOfContextMap();
            if (copy != null) {
                seen.putAll(copy);
            }
        });
        return seen;
    }

    @Test
    @DisplayName("EVT-03 (통합) 기본 체인: 요청·사용자 MDC 키가 v2 이름으로 들어가고, 응답에 X-Request-Id, 요청이 끝나면 지운다")
    void mdcKeys() {
        runner.run(context -> {
            FilterChainProxy chain = context.getBean("springSecurityFilterChain", FilterChainProxy.class);
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockHttpServletRequest request = get("/api/me", new Cookie("__Host-demo_at", "eyJ.at"));
            request.addHeader("X-Request-Id", "req-1");
            request.addHeader("User-Agent", "kss-test");
            request.setRemoteAddr("10.1.2.3");

            Map<String, String> mdc = sendAndCaptureMdc(chain, request, response);

            assertThat(response.getStatus()).isEqualTo(200);
            assertThat(mdc).containsEntry("traceId", "req-1").containsEntry("httpMethod", "GET").containsEntry("requestUri", "/api/me")
                .containsEntry("clientIp", "10.1.2.3").containsEntry("userAgent", "kss-test")
                .containsEntry("userId", "user-1").containsEntry("sessionId", "kc-sid-1")
                .doesNotContainKeys("queryString", "status", "durationMs");
            assertThat(mdc.values()).as("토큰·쿠키 값은 MDC에 없다").noneMatch(v -> v.contains("eyJ"));
            assertThat(response.getHeader("X-Request-Id")).isEqualTo("req-1");
            assertThat(MDC.getCopyOfContextMap()).isNullOrEmpty();
        });
    }

    @Test
    @DisplayName("EVT-03 (통합) 인증에 실패한 요청(401)도 traceId를 남기고 응답에 돌려준다. 사용자 키는 없다")
    void mdcOnUnauthenticated() {
        runner.run(context -> {
            FilterChainProxy chain = context.getBean("springSecurityFilterChain", FilterChainProxy.class);
            MockHttpServletResponse response = new MockHttpServletResponse();

            Map<String, String> mdc = sendAndCaptureMdc(chain, get("/api/me"), response);

            assertThat(response.getStatus()).isEqualTo(401);
            assertThat(response.getHeader("X-Request-Id")).hasSize(36);
            assertThat(mdc).as("401은 체인 끝까지 가지 않는다").isEmpty();
        });
    }

    @Test
    @DisplayName("EVT-03 (통합) keycloak.security.logging.*·trusted-proxy-count를 읽고, 이 타입의 빈을 올리면 그것을 쓴다")
    void mdcSettingsAndOverride() {
        Map<String, String> custom = new HashMap<>();
        LoggingContextAccessor accessor = new LoggingContextAccessor() {
            @Override
            public void put(String key, String value) {
                custom.put(key, value);
            }

            @Override
            public String get(String key) {
                return custom.get(key);
            }

            @Override
            public void remove(String key) {
                custom.remove(key);
            }

            @Override
            public void clear() {
            }
        };
        runner.withPropertyValues("keycloak.security.logging.include-query-string=true", "keycloak.security.logging.include-user-agent=false",
                "keycloak.security.logging.exclude-patterns=/health/**", "keycloak.security.trusted-proxy-count=1")
            .withBean(LoggingContextAccessor.class, () -> accessor)
            .run(context -> {
                KeycloakSecuritySettings settings = context.getBean(KeycloakSecuritySettings.class);
                assertThat(settings.logging().includeQueryString()).isTrue();
                assertThat(settings.logging().excludePatterns()).containsExactly("/health/**");
                assertThat(settings.trustedProxyCount()).isEqualTo(1);

                FilterChainProxy chain = context.getBean("springSecurityFilterChain", FilterChainProxy.class);
                MockHttpServletRequest request = get("/api/me", new Cookie("__Host-demo_at", "eyJ.at"));
                request.setQueryString("email=alice@example.com");
                request.addHeader("X-Forwarded-For", "fake, 203.0.113.7");
                request.addHeader("User-Agent", "kss-test");
                send(chain, request, new MockHttpServletResponse());

                assertThat(custom).containsEntry("queryString", "email=a***@example.com").containsEntry("clientIp", "203.0.113.7")
                    .containsEntry("userId", "user-1").doesNotContainKey("userAgent");
            });
    }
}
