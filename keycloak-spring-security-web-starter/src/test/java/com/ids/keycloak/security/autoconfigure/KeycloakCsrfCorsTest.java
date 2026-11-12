package com.ids.keycloak.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.web.cors.CorsConfigurationSource;

import com.ids.keycloak.security.crypto.KeycloakCsrfTokenSigner;
import com.ids.keycloak.security.session.SessionIds;
import com.ids.keycloak.security.web.config.KeycloakHttpConfigurer;
import com.ids.keycloak.security.web.csrf.SignedDoubleSubmitCsrfTokenRepository;

import jakarta.servlet.http.Cookie;

/**
 * V3-10 CSRF·Origin·CORS를 자동 설정의 기본 보안 체인 그대로 돌려 본다 (통합). 실제 브라우저 흐름은 E2E(E2eCsrfTest)가 본다.
 */
class KeycloakCsrfCorsTest {

    static final String FRONTEND = "https://app.example.com";
    static final Pattern TOKEN = Pattern.compile("\"token\":\"([^\"]+)\"");

    final WebApplicationContextRunner runner = KeycloakSecurityAutoConfigurationTest
        .runnerWith(KeycloakSecurityAutoConfigurationTest.registration(KeycloakSecurityAutoConfigurationTest.ISSUER));

    static MockHttpServletResponse send(FilterChainProxy chain, MockHttpServletRequest request) throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        chain.doFilter(request, response, (req, res) -> ((jakarta.servlet.http.HttpServletResponse) res).setStatus(201));
        return response;
    }

    static MockHttpServletRequest request(String method, String path, Cookie... cookies) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        if (cookies.length > 0) {
            request.setCookies(cookies);
        }
        return request;
    }

    @Test
    @DisplayName("기본 빈: CSRF 저장소는 sid 서명 double-submit, CORS는 이름 keycloakCorsConfigurationSource")
    void beans() {
        runner.run(context -> {
            assertThat(context.getBean(CsrfTokenRepository.class)).isInstanceOf(SignedDoubleSubmitCsrfTokenRepository.class);
            assertThat(context.getBean(KeycloakHttpConfigurer.CORS_CONFIGURATION_SOURCE_BEAN, CorsConfigurationSource.class)).isNotNull();
        });
    }

    @Test
    @DisplayName("다른 CorsConfigurationSource 빈(Spring MVC의 것 등)이 있어도 라이브러리 CORS 빈은 올라간다. 같은 이름으로 올리면 그것을 쓴다")
    void corsBeanByName() {
        CorsConfigurationSource mvc = request -> null;
        runner.withBean("mvcHandlerMappingIntrospector", CorsConfigurationSource.class, () -> mvc)
            .run(context -> assertThat(context.getBean(KeycloakHttpConfigurer.CORS_CONFIGURATION_SOURCE_BEAN)).isNotSameAs(mvc));
        CorsConfigurationSource custom = request -> null;
        runner.withBean(KeycloakHttpConfigurer.CORS_CONFIGURATION_SOURCE_BEAN, CorsConfigurationSource.class, () -> custom)
            .run(context -> assertThat(context.getBean(KeycloakHttpConfigurer.CORS_CONFIGURATION_SOURCE_BEAN)).isSameAs(custom));
    }

    @Test
    @DisplayName("CSRF-01·02·03 (통합) 토큰 없는 POST는 403 INVALID_CSRF_TOKEN, /api/csrf로 받은 토큰을 헤더에 넣으면 CSRF를 지난다")
    void csrfFlow() {
        runner.run(context -> {
            FilterChainProxy chain = context.getBean("springSecurityFilterChain", FilterChainProxy.class);
            String sid = SessionIds.newSid();
            Cookie sidCookie = new Cookie("__Host-demo_sid", sid);
            Cookie csrfCookie = new Cookie("__Host-demo_csrf", context.getBean(KeycloakCsrfTokenSigner.class).create(sid));

            MockHttpServletRequest withoutToken = request("POST", "/api/items", sidCookie, csrfCookie);
            withoutToken.addHeader("Origin", FRONTEND);
            MockHttpServletResponse rejected = send(chain, withoutToken);
            assertThat(rejected.getStatus()).isEqualTo(403);
            assertThat(rejected.getContentAsString()).contains("\"code\":\"INVALID_CSRF_TOKEN\"");

            MockHttpServletResponse tokenResponse = send(chain, request("GET", "/api/csrf", sidCookie, csrfCookie));
            assertThat(tokenResponse.getStatus()).isEqualTo(200);
            assertThat(tokenResponse.getContentAsString()).contains("\"headerName\":\"X-XSRF-TOKEN\"", "\"parameterName\":\"_csrf\"");
            assertThat(tokenResponse.getHeaders("Set-Cookie")).as("쿠키에 토큰이 있으면 새로 쓰지 않는다").isEmpty();
            Matcher token = TOKEN.matcher(tokenResponse.getContentAsString());
            assertThat(token.find()).isTrue();

            MockHttpServletRequest withToken = request("POST", "/api/items", sidCookie, csrfCookie);
            withToken.addHeader("Origin", FRONTEND);
            withToken.addHeader("X-XSRF-TOKEN", token.group(1));
            MockHttpServletResponse passed = send(chain, withToken);
            assertThat(passed.getStatus()).as("CSRF를 지나 인증 단계(at 쿠키 없음, 갱신할 행 없음)에서 401").isEqualTo(401);
        });
    }

    @Test
    @DisplayName("CSRF-05 (통합) 다른 화면 Origin은 CORS가 403(허용 헤더 없음), Origin·Referer가 없거나 API 자신의 Origin이면 403 ORIGIN_NOT_ALLOWED")
    void originChecks() {
        runner.run(context -> {
            FilterChainProxy chain = context.getBean("springSecurityFilterChain", FilterChainProxy.class);

            MockHttpServletRequest evil = request("POST", "/api/items");
            evil.addHeader("Origin", "https://evil.example.com");
            MockHttpServletResponse byCors = send(chain, evil);
            assertThat(byCors.getStatus()).isEqualTo(403);
            assertThat(byCors.getHeader("Access-Control-Allow-Origin")).isNull();

            MockHttpServletResponse noOrigin = send(chain, request("POST", "/api/items"));
            assertThat(noOrigin.getStatus()).isEqualTo(403);
            assertThat(noOrigin.getContentAsString()).contains("\"code\":\"ORIGIN_NOT_ALLOWED\"");

            MockHttpServletRequest sameOrigin = request("POST", "/api/items");
            sameOrigin.addHeader("Origin", "http://localhost");
            MockHttpServletResponse self = send(chain, sameOrigin);
            assertThat(self.getStatus()).isEqualTo(403);
            assertThat(self.getContentAsString()).contains("\"code\":\"ORIGIN_NOT_ALLOWED\"");
        });
    }

    @Test
    @DisplayName("CORS-01·02 (통합) 화면 Origin의 사전 확인은 200과 허용 헤더, 다른 Origin은 허용 헤더 없음")
    void preflight() {
        runner.run(context -> {
            FilterChainProxy chain = context.getBean("springSecurityFilterChain", FilterChainProxy.class);
            MockHttpServletRequest allowed = request("OPTIONS", "/api/items");
            allowed.addHeader("Origin", FRONTEND);
            allowed.addHeader("Access-Control-Request-Method", "POST");
            allowed.addHeader("Access-Control-Request-Headers", "content-type,x-xsrf-token");
            MockHttpServletResponse ok = send(chain, allowed);
            assertThat(ok.getStatus()).isEqualTo(200);
            assertThat(ok.getHeader("Access-Control-Allow-Origin")).isEqualTo(FRONTEND);
            assertThat(ok.getHeader("Access-Control-Allow-Credentials")).isEqualTo("true");
            assertThat(ok.getHeader("Access-Control-Allow-Headers")).containsIgnoringCase("x-xsrf-token");

            MockHttpServletRequest other = request("OPTIONS", "/api/items");
            other.addHeader("Origin", "https://evil.example.com");
            other.addHeader("Access-Control-Request-Method", "POST");
            MockHttpServletResponse denied = send(chain, other);
            assertThat(denied.getHeader("Access-Control-Allow-Origin")).isNull();
        });
    }

    @Test
    @DisplayName("CORS-03 (통합) 허용 헤더는 Content-Type·X-XSRF-TOKEN·X-Background 셋뿐: X-Requested-With·Authorization만 물으면 403, 섞어 물으면 그 헤더는 답에 없다")
    void preflightAllowsOnlyThreeHeaders() {
        runner.run(context -> {
            FilterChainProxy chain = context.getBean("springSecurityFilterChain", FilterChainProxy.class);
            MockHttpServletRequest three = request("OPTIONS", "/api/items");
            three.addHeader("Origin", FRONTEND);
            three.addHeader("Access-Control-Request-Method", "POST");
            three.addHeader("Access-Control-Request-Headers", "content-type,x-xsrf-token,x-background");
            MockHttpServletResponse ok = send(chain, three);
            assertThat(ok.getStatus()).isEqualTo(200);
            assertThat(ok.getHeader("Access-Control-Allow-Headers"))
                .containsIgnoringCase("content-type").containsIgnoringCase("x-xsrf-token").containsIgnoringCase("x-background");

            for (String header : new String[] {"x-requested-with", "authorization"}) {
                MockHttpServletRequest only = request("OPTIONS", "/api/items");
                only.addHeader("Origin", FRONTEND);
                only.addHeader("Access-Control-Request-Method", "POST");
                only.addHeader("Access-Control-Request-Headers", header);
                MockHttpServletResponse denied = send(chain, only);
                assertThat(denied.getStatus()).as(header).isEqualTo(403);
                assertThat(denied.getHeader("Access-Control-Allow-Origin")).as(header).isNull();

                // 허용 헤더와 섞어 물으면 Spring은 200에 허용된 것만 답한다. 브라우저는 답에 없는 헤더를 보고 실제 요청을 막는다
                MockHttpServletRequest mixed = request("OPTIONS", "/api/items");
                mixed.addHeader("Origin", FRONTEND);
                mixed.addHeader("Access-Control-Request-Method", "POST");
                mixed.addHeader("Access-Control-Request-Headers", "content-type," + header);
                MockHttpServletResponse partial = send(chain, mixed);
                assertThat(partial.getHeader("Access-Control-Allow-Headers")).as(header)
                    .containsIgnoringCase("content-type").doesNotContainIgnoringCase(header);
            }
        });
    }

    @Test
    @DisplayName("BCL-04 (통합) back-channel 주소는 CSRF·Origin 없이 받는다: 틀린 logout_token은 403이 아니라 400 invalid_request, 처리기 빈은 기본값")
    void backChannelSkipsCsrfAndOrigin() {
        runner.run(context -> {
            assertThat(context.getBean(com.ids.keycloak.security.web.logout.KeycloakBackChannelLogoutHandler.class)).isNotNull();
            FilterChainProxy chain = context.getBean("springSecurityFilterChain", FilterChainProxy.class);
            MockHttpServletRequest request = request("POST", "/logout/connect/back-channel/keycloak");
            request.setContentType("application/x-www-form-urlencoded");
            request.addParameter("logout_token", "not.a.jwt");

            MockHttpServletResponse response = send(chain, request);

            assertThat(response.getStatus()).isEqualTo(400);
            assertThat(response.getContentAsString()).contains("invalid_request");
            assertThat(response.getHeaders("Set-Cookie")).isEmpty();
        });
    }
}
