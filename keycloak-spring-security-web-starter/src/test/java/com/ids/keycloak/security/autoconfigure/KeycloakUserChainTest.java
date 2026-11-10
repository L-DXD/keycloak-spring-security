package com.ids.keycloak.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.Principal;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

import com.ids.keycloak.security.crypto.TokenCipher;
import com.ids.keycloak.security.session.KeycloakSessionRecord;
import com.ids.keycloak.security.session.KeycloakSessionStore;
import com.ids.keycloak.security.session.SessionIds;
import com.ids.keycloak.security.token.AccessTokenValidationResult;
import com.ids.keycloak.security.token.KeycloakAccessTokenValidator;
import com.ids.keycloak.security.web.config.KeycloakHttpConfigurer;
import com.ids.keycloak.security.web.refresh.KeycloakTokenClient;
import com.ids.keycloak.security.web.refresh.KeycloakTokenResponse;

import jakarta.servlet.http.Cookie;

/**
 * V3-14 사용자 보안 체인 (#90, EXT-02·06): 앱이 {@link SecurityFilterChain}을 올리고 {@link KeycloakHttpConfigurer}를 붙이면 그 체인에서
 * 로그인 시작·요청 인증·갱신·로그아웃이 기본 체인과 같이 된다. 앱 체인이 일부 주소만 받으면 기본 체인은 남아 나머지를 지킨다(fail-open 없음).
 * 기본 체인은 같은 이름의 빈이나 {@code auto-filter-chain=false}로만 빠진다. Keycloak 대신 토큰 검증기와 토큰 클라이언트만 바꾼다
 * (실제 Keycloak 흐름은 E2E가 기본 체인으로 본다).
 */
class KeycloakUserChainTest {

    static final String FRONTEND = "https://app.example.com";
    static final Pattern CSRF_TOKEN = Pattern.compile("\"token\":\"([^\"]+)\"");

    /** 앱의 체인: 01 설계 4-3의 예. */
    @Configuration(proxyBeanMethods = false)
    @EnableWebSecurity
    static class UserChain {

        @Bean
        SecurityFilterChain api(HttpSecurity http) throws Exception {
            return http
                .securityMatcher("/api/**", "/oauth2/**", "/login/oauth2/**", "/logout/**")
                .authorizeHttpRequests(a -> a.requestMatchers("/api/public/**").permitAll().anyRequest().authenticated())
                .with(KeycloakHttpConfigurer.keycloak(), Customizer.withDefaults())
                .build();
        }
    }

    /** Customizer를 붙인 체인: 로그인·CORS·CSRF는 불렸는지 적고, 로그아웃 뒤 응답은 204로 바꾼다. 같은 이름이라 기본 체인 대신 쓰인다. */
    @Configuration(proxyBeanMethods = false)
    @EnableWebSecurity
    static class CustomizedChain {

        static final List<String> CALLED = new CopyOnWriteArrayList<>();

        @Bean(name = "keycloakSecurityFilterChain")
        SecurityFilterChain api(HttpSecurity http) throws Exception {
            return http
                .authorizeHttpRequests(a -> a.anyRequest().authenticated())
                .with(KeycloakHttpConfigurer.keycloak()
                    .login(l -> CALLED.add("login"))
                    .cors(c -> CALLED.add("cors"))
                    .csrf(c -> CALLED.add("csrf"))
                    .logout(l -> l.logoutSuccessHandler((request, response, authentication) -> response.setStatus(204))),
                    Customizer.withDefaults())
                .build();
        }
    }

    /** 운영 주소만 따로 여는 체인 (라이브러리 설정기 없음). v2 1.5.0 fail-open을 다시 만드는 흔한 모양. */
    @Configuration(proxyBeanMethods = false)
    @EnableWebSecurity
    static class ActuatorChain {

        @Bean
        @Order(0)
        SecurityFilterChain actuator(HttpSecurity http) throws Exception {
            return http.securityMatcher("/actuator/**").authorizeHttpRequests(a -> a.anyRequest().permitAll()).build();
        }
    }

    /** 모든 주소를 받는 앱 체인 (다른 이름). */
    @Configuration(proxyBeanMethods = false)
    @EnableWebSecurity
    static class CatchAllChain {

        @Bean
        SecurityFilterChain app(HttpSecurity http) throws Exception {
            return http.authorizeHttpRequests(a -> a.anyRequest().authenticated())
                .with(KeycloakHttpConfigurer.keycloak(), Customizer.withDefaults())
                .build();
        }
    }

    /** 가짜 Keycloak 토큰 주소: 갱신하면 eyJ.at2·rt-2를 준다. 받은 리프레시 토큰을 적어 둔다. */
    static final class FakeTokenClient implements KeycloakTokenClient {
        final List<String> refreshed = new CopyOnWriteArrayList<>();
        final List<String> loggedOut = new CopyOnWriteArrayList<>();

        @Override
        public KeycloakTokenResponse refresh(String refreshToken) {
            refreshed.add(refreshToken);
            return new KeycloakTokenResponse("eyJ.at2", "rt-2", null);
        }

        @Override
        public void logout(String refreshToken) {
            loggedOut.add(refreshToken);
        }

        @Override
        public void revoke(String refreshToken) {
        }
    }

    final FakeTokenClient tokenClient = new FakeTokenClient();

    final WebApplicationContextRunner runner = KeycloakSecurityAutoConfigurationTest
        .baseRunner(KeycloakSecurityAutoConfigurationTest.registration(KeycloakSecurityAutoConfigurationTest.ISSUER))
        .withPropertyValues("keycloak.security.session.store=memory")
        .withUserConfiguration(UserChain.class)
        .withBean(KeycloakTokenClient.class, () -> tokenClient)
        .withBean(KeycloakAccessTokenValidator.class, () -> token -> token.startsWith("eyJ.at")
            ? AccessTokenValidationResult.valid(jwt(token))
            : AccessTokenValidationResult.invalid("서명이 맞지 않습니다"));

    static Jwt jwt(String token) {
        Instant now = Instant.now();
        return Jwt.withTokenValue(token).header("alg", "RS256").subject("user-1").claim("sid", "kc-sid-1").claim("azp", "demo")
            .issuedAt(now).expiresAt(now.plusSeconds(60)).build();
    }

    static MockHttpServletRequest request(String method, String path, Cookie... cookies) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        if (cookies.length > 0) {
            request.setCookies(cookies);
        }
        return request;
    }

    static String setCookieValue(MockHttpServletResponse response, String name) {
        return response.getHeaders("Set-Cookie").stream().filter(h -> h.startsWith(name + "="))
            .map(h -> h.substring(name.length() + 1, h.indexOf(';'))).findFirst().orElse(null);
    }

    @Test
    @DisplayName("EXT-02 앱 체인이 일부 주소만 받으면 기본 체인은 맨 뒤에 남아 나머지 주소를 지킨다")
    void defaultChainStaysBehindPartialUserChain() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.containsBean("keycloakSecurityFilterChain")).isTrue();
            FilterChainProxy chain = context.getBean("springSecurityFilterChain", FilterChainProxy.class);
            assertThat(chain.getFilterChains()).hasSize(2);
            assertThat(chain.getFilterChains().get(1)).isSameAs(context.getBean("keycloakSecurityFilterChain"));
            assertThat(KeycloakCsrfCorsTest.send(chain, request("GET", "/reports/1")).getStatus()).as("앱 체인 밖 주소").isEqualTo(401);
        });
    }

    @Test
    @DisplayName("EXT-06 앱이 운영 주소 체인(/actuator/**)만 더해도 기본 체인이 빠지지 않아 나머지 주소는 로그인 없이 열리지 않는다 (v2 1.5.0 fail-open 재발 방지)")
    void actuatorChainDoesNotOpenTheRest() {
        KeycloakSecurityAutoConfigurationTest
            .baseRunner(KeycloakSecurityAutoConfigurationTest.registration(KeycloakSecurityAutoConfigurationTest.ISSUER))
            .withPropertyValues("keycloak.security.session.store=memory")
            .withUserConfiguration(ActuatorChain.class)
            .run(context -> {
                assertThat(context).hasNotFailed();
                FilterChainProxy chain = context.getBean("springSecurityFilterChain", FilterChainProxy.class);
                assertThat(chain.getFilterChains()).hasSize(2);
                assertThat(KeycloakCsrfCorsTest.send(chain, request("GET", "/actuator/health")).getStatus()).isEqualTo(201);
                assertThat(KeycloakCsrfCorsTest.send(chain, request("GET", "/api/me")).getStatus()).isEqualTo(401);
                assertThat(KeycloakCsrfCorsTest.send(chain, request("POST", "/api/items")).getStatus()).isIn(401, 403);
            });
    }

    @Test
    @DisplayName("EXT-06 기본 체인은 keycloak.security.auto-filter-chain=false일 때만 빠진다")
    void autoFilterChainOff() {
        runner.withPropertyValues("keycloak.security.auto-filter-chain=false").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.containsBean("keycloakSecurityFilterChain")).isFalse();
            assertThat(context.getBean("springSecurityFilterChain", FilterChainProxy.class).getFilterChains()).hasSize(1);
        });
    }

    @Test
    @DisplayName("EXT-06 앱도 모든 주소를 받는 체인을 다른 이름으로 올리면 기동하지 않는다 (같은 이름으로 바꾸거나 auto-filter-chain=false)")
    void twoCatchAllChainsStopStartup() {
        KeycloakSecurityAutoConfigurationTest
            .baseRunner(KeycloakSecurityAutoConfigurationTest.registration(KeycloakSecurityAutoConfigurationTest.ISSUER))
            .withPropertyValues("keycloak.security.session.store=memory")
            .withUserConfiguration(CatchAllChain.class)
            .run(context -> assertThat(context).getFailure().rootCause().hasMessageContaining("any request"));
        KeycloakSecurityAutoConfigurationTest
            .baseRunner(KeycloakSecurityAutoConfigurationTest.registration(KeycloakSecurityAutoConfigurationTest.ISSUER))
            .withPropertyValues("keycloak.security.session.store=memory", "keycloak.security.auto-filter-chain=false")
            .withUserConfiguration(CatchAllChain.class)
            .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    @DisplayName("EXT-02 사용자 체인에서 로그인 시작(PKCE S256·login 쿠키) → 요청 인증 → 갱신 → 로그아웃(CSRF)이 된다")
    void loginRefreshLogout() {
        runner.run(context -> {
            FilterChainProxy chain = context.getBean("springSecurityFilterChain", FilterChainProxy.class);

            // 로그인 시작: Keycloak 인증 주소로 302, PKCE S256, 로그인 임시 쿠키
            MockHttpServletResponse login = KeycloakCsrfCorsTest.send(chain, request("GET", "/oauth2/authorization/keycloak"));
            assertThat(login.getStatus()).isEqualTo(302);
            assertThat(login.getRedirectedUrl()).startsWith(KeycloakSecurityAutoConfigurationTest.ISSUER + "/protocol/openid-connect/auth?")
                .contains("code_challenge_method=S256");
            assertThat(setCookieValue(login, "__Host-demo_login")).isNotBlank();

            // 요청 인증: at 쿠키
            MockHttpServletResponse me = new MockHttpServletResponse();
            Principal principal = KeycloakRequestAuthenticationTest.send(chain, request("GET", "/api/me", new Cookie("__Host-demo_at", "eyJ.at")), me);
            assertThat(me.getStatus()).isEqualTo(200);
            assertThat(principal.getName()).isEqualTo("user-1");

            // 갱신: at 없이 sid만 → 행의 리프레시 토큰으로 갱신하고 새 at 쿠키
            KeycloakSessionStore store = context.getBean(KeycloakSessionStore.class);
            String sid = SessionIds.newSid();
            Instant now = Instant.now();
            store.insert(new KeycloakSessionRecord(UUID.randomUUID(), SessionIds.hash(sid), "user-1", "kc-sid-1",
                context.getBean(TokenCipher.class).encrypt("rt-1"), now.plusSeconds(1800), now, now.plusSeconds(43200), null));
            Cookie sidCookie = new Cookie("__Host-demo_sid", sid);
            MockHttpServletResponse refreshed = new MockHttpServletResponse();
            KeycloakRequestAuthenticationTest.send(chain, request("GET", "/api/me", sidCookie), refreshed);
            assertThat(refreshed.getStatus()).isEqualTo(200);
            assertThat(setCookieValue(refreshed, "__Host-demo_at")).isEqualTo("eyJ.at2");
            assertThat(tokenClient.refreshed).containsExactly("rt-1");

            // 로그아웃: /api/csrf로 토큰을 받아 POST /logout
            MockHttpServletResponse csrf = KeycloakCsrfCorsTest.send(chain, request("GET", "/api/csrf", sidCookie));
            Matcher token = CSRF_TOKEN.matcher(csrf.getContentAsString());
            assertThat(token.find()).isTrue();
            MockHttpServletRequest logoutRequest = request("POST", "/logout", sidCookie,
                new Cookie("__Host-demo_csrf", setCookieValue(csrf, "__Host-demo_csrf")));
            logoutRequest.addHeader("Origin", FRONTEND);
            logoutRequest.addHeader("X-XSRF-TOKEN", token.group(1));
            MockHttpServletResponse logout = KeycloakCsrfCorsTest.send(chain, logoutRequest);

            assertThat(logout.getStatus()).isEqualTo(302);
            assertThat(logout.getRedirectedUrl()).isEqualTo(FRONTEND + "/");
            assertThat(store.findBySidHash(SessionIds.hash(sid))).isEmpty();
            assertThat(tokenClient.loggedOut).as("갱신으로 바뀐 리프레시 토큰으로 Keycloak 로그아웃").containsExactly("rt-2");
            assertThat(logout.getHeaders("Set-Cookie")).anyMatch(h -> h.startsWith("__Host-demo_sid=;") && h.contains("Max-Age=0"));
        });
    }

    @Test
    @DisplayName("EXT-02 설정기의 Customizer(login·csrf·cors·logout)는 라이브러리 설정 뒤에 불려 사용자 값이 이긴다. 라이브러리 처리기는 그대로 돈다")
    void customizers() {
        CustomizedChain.CALLED.clear();
        KeycloakSecurityAutoConfigurationTest
            .baseRunner(KeycloakSecurityAutoConfigurationTest.registration(KeycloakSecurityAutoConfigurationTest.ISSUER))
            .withPropertyValues("keycloak.security.session.store=memory")
            .withUserConfiguration(CustomizedChain.class)
            .withBean(KeycloakTokenClient.class, () -> tokenClient)
            .run(context -> {
                assertThat(context).hasNotFailed();
                assertThat(context.getBean("springSecurityFilterChain", FilterChainProxy.class).getFilterChains()).as("같은 이름이라 기본 체인 대신").hasSize(1);
                assertThat(CustomizedChain.CALLED).containsExactlyInAnyOrder("login", "cors", "csrf");
                FilterChainProxy chain = context.getBean("springSecurityFilterChain", FilterChainProxy.class);

                KeycloakSessionStore store = context.getBean(KeycloakSessionStore.class);
                String sid = SessionIds.newSid();
                Instant now = Instant.now();
                store.insert(new KeycloakSessionRecord(UUID.randomUUID(), SessionIds.hash(sid), "user-1", "kc-sid-1",
                    context.getBean(TokenCipher.class).encrypt("rt-1"), now.plusSeconds(1800), now, now.plusSeconds(43200), null));
                Cookie sidCookie = new Cookie("__Host-demo_sid", sid);
                MockHttpServletResponse csrf = KeycloakCsrfCorsTest.send(chain, request("GET", "/api/csrf", sidCookie));
                Matcher token = CSRF_TOKEN.matcher(csrf.getContentAsString());
                assertThat(token.find()).isTrue();
                MockHttpServletRequest logoutRequest = request("POST", "/logout", sidCookie,
                    new Cookie("__Host-demo_csrf", setCookieValue(csrf, "__Host-demo_csrf")));
                logoutRequest.addHeader("Origin", FRONTEND);
                logoutRequest.addHeader("X-XSRF-TOKEN", token.group(1));

                MockHttpServletResponse logout = KeycloakCsrfCorsTest.send(chain, logoutRequest);

                assertThat(logout.getStatus()).as("사용자 로그아웃 뒤 처리기").isEqualTo(204);
                assertThat(store.findBySidHash(SessionIds.hash(sid))).as("라이브러리 로그아웃 처리기는 그대로").isEmpty();
                assertThat(tokenClient.loggedOut).containsExactly("rt-1");
            });
    }
}
