package com.ids.keycloak.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.Principal;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
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
}
