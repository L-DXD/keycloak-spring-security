package com.ids.keycloak.security.web.reactive;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.config.KeycloakErrorProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.BadCredentialsException;
import reactor.test.StepVerifier;

/**
 * KeycloakServerAuthenticationEntryPoint 분기 단위 테스트.
 * - Bearer Token 요청 → WWW-Authenticate: Bearer + 401
 * - Basic Auth 요청 + basicAuthEnabled=true → WWW-Authenticate: Basic + 401
 * - redirectEnabled=true + AJAX → JSON 401
 * - redirectEnabled=true (비-AJAX) → 302 리다이렉트
 * - API 모드 기본 → JSON 401
 */
class KeycloakServerAuthenticationEntryPointTest {

  private ObjectMapper objectMapper;

  @BeforeEach
  void setUp() {
    objectMapper = new ObjectMapper();
  }

  // =========================================================
  // API 모드 (기본)
  // =========================================================
  @Nested
  @DisplayName("API 모드 (redirect-enabled=false)")
  class API_모드 {

    @Test
    @DisplayName("Bearer 헤더 요청 → 401 + WWW-Authenticate: Bearer")
    void Bearer_요청_401_WWW_Authenticate() {
      var entryPoint = new KeycloakServerAuthenticationEntryPoint(
          objectMapper, new KeycloakErrorProperties(), false, "myrealm");

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/api/resource")
              .header(HttpHeaders.AUTHORIZATION, "Bearer some.token.here")
              .build());

      StepVerifier.create(entryPoint.commence(exchange, new BadCredentialsException("bad")))
          .verifyComplete();

      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
      String wwwAuth = exchange.getResponse().getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
      assertThat(wwwAuth).startsWith("Bearer realm=\"myrealm\"");
    }

    @Test
    @DisplayName("Basic 헤더 요청 + basicAuthEnabled=true → 401 + WWW-Authenticate: Basic")
    void Basic_요청_WWW_Authenticate() {
      var entryPoint = new KeycloakServerAuthenticationEntryPoint(
          objectMapper, new KeycloakErrorProperties(), true, "myrealm");

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/api/resource")
              .header(HttpHeaders.AUTHORIZATION, "Basic dXNlcjpwYXNz")
              .build());

      StepVerifier.create(entryPoint.commence(exchange, new BadCredentialsException("bad")))
          .verifyComplete();

      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
      String wwwAuth = exchange.getResponse().getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
      assertThat(wwwAuth).startsWith("Basic realm=\"myrealm\"");
    }

    @Test
    @DisplayName("Basic 헤더 요청 + basicAuthEnabled=false → WWW-Authenticate 없이 401 JSON")
    void Basic_요청_basicAuth_비활성화시_JSON() {
      var entryPoint = new KeycloakServerAuthenticationEntryPoint(
          objectMapper, new KeycloakErrorProperties(), false, "myrealm");

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/api/resource")
              .header(HttpHeaders.AUTHORIZATION, "Basic dXNlcjpwYXNz")
              .build());

      StepVerifier.create(entryPoint.commence(exchange, new BadCredentialsException("bad")))
          .verifyComplete();

      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
      assertThat(exchange.getResponse().getHeaders().containsKey(HttpHeaders.WWW_AUTHENTICATE)).isFalse();
    }

    @Test
    @DisplayName("일반 요청 → 401 JSON 응답")
    void 일반_요청_401_JSON() {
      var entryPoint = new KeycloakServerAuthenticationEntryPoint(objectMapper);

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/api/resource").build());

      StepVerifier.create(entryPoint.commence(exchange, new BadCredentialsException("bad")))
          .verifyComplete();

      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
  }

  // =========================================================
  // Redirect 모드
  // =========================================================
  @Nested
  @DisplayName("Redirect 모드 (redirect-enabled=true)")
  class Redirect_모드 {

    @Test
    @DisplayName("비-AJAX 요청 → 302 리다이렉트")
    void 비_AJAX_리다이렉트() {
      KeycloakErrorProperties errorProps = new KeycloakErrorProperties();
      errorProps.setRedirectEnabled(true);
      errorProps.setAuthenticationFailedRedirectUrl("/login");

      var entryPoint = new KeycloakServerAuthenticationEntryPoint(
          objectMapper, errorProps, false, null);

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/protected").build());

      StepVerifier.create(entryPoint.commence(exchange, new BadCredentialsException("bad")))
          .verifyComplete();

      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
      assertThat(exchange.getResponse().getHeaders().getLocation().getPath()).isEqualTo("/login");
    }

    @Test
    @DisplayName("AJAX 요청 + ajaxReturnsJson=true → 401 JSON")
    void AJAX_요청_JSON() {
      KeycloakErrorProperties errorProps = new KeycloakErrorProperties();
      errorProps.setRedirectEnabled(true);
      errorProps.setAjaxReturnsJson(true);
      errorProps.setAuthenticationFailedRedirectUrl("/login");

      var entryPoint = new KeycloakServerAuthenticationEntryPoint(
          objectMapper, errorProps, false, null);

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/protected")
              .header("X-Requested-With", "XMLHttpRequest")
              .build());

      StepVerifier.create(entryPoint.commence(exchange, new BadCredentialsException("bad")))
          .verifyComplete();

      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("브라우저 Accept(text/html,...,*/*) → 비-AJAX → 302 리다이렉트")
    void 브라우저_Accept_비AJAX_리다이렉트() {
      KeycloakErrorProperties errorProps = new KeycloakErrorProperties();
      errorProps.setRedirectEnabled(true);
      errorProps.setAjaxReturnsJson(true);
      errorProps.setAuthenticationFailedRedirectUrl("/login");

      var entryPoint = new KeycloakServerAuthenticationEntryPoint(
          objectMapper, errorProps, false, null);

      // 브라우저 표준 Accept 헤더: text/html 포함 + */* 포함
      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/protected")
              .accept(MediaType.TEXT_HTML,
                  MediaType.parseMediaType("application/xhtml+xml"),
                  MediaType.parseMediaType("application/xml;q=0.9"),
                  MediaType.ALL)
              .build());

      StepVerifier.create(entryPoint.commence(exchange, new BadCredentialsException("bad")))
          .verifyComplete();

      // 브라우저 요청은 AJAX가 아니므로 302 리다이렉트
      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
      assertThat(exchange.getResponse().getHeaders().getLocation().getPath()).isEqualTo("/login");
    }

    @Test
    @DisplayName("Accept: application/json 단독 → AJAX → 401 JSON")
    void Accept_application_json_단독_AJAX() {
      KeycloakErrorProperties errorProps = new KeycloakErrorProperties();
      errorProps.setRedirectEnabled(true);
      errorProps.setAjaxReturnsJson(true);
      errorProps.setAuthenticationFailedRedirectUrl("/login");

      var entryPoint = new KeycloakServerAuthenticationEntryPoint(
          objectMapper, errorProps, false, null);

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/protected")
              .accept(MediaType.APPLICATION_JSON)
              .build());

      StepVerifier.create(entryPoint.commence(exchange, new BadCredentialsException("bad")))
          .verifyComplete();

      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("Accept: */* 단독 → 비-AJAX → 302 리다이렉트")
    void Accept_wildcard_단독_비AJAX_리다이렉트() {
      KeycloakErrorProperties errorProps = new KeycloakErrorProperties();
      errorProps.setRedirectEnabled(true);
      errorProps.setAjaxReturnsJson(true);
      errorProps.setAuthenticationFailedRedirectUrl("/login");

      var entryPoint = new KeycloakServerAuthenticationEntryPoint(
          objectMapper, errorProps, false, null);

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/protected")
              .accept(MediaType.ALL)
              .build());

      StepVerifier.create(entryPoint.commence(exchange, new BadCredentialsException("bad")))
          .verifyComplete();

      // */* 단독은 AJAX가 아니므로 302 리다이렉트
      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
    }

    @Test
    @DisplayName("Accept 헤더 없음 → 비-AJAX → 302 리다이렉트")
    void Accept_헤더_없음_비AJAX_리다이렉트() {
      KeycloakErrorProperties errorProps = new KeycloakErrorProperties();
      errorProps.setRedirectEnabled(true);
      errorProps.setAjaxReturnsJson(true);
      errorProps.setAuthenticationFailedRedirectUrl("/login");

      var entryPoint = new KeycloakServerAuthenticationEntryPoint(
          objectMapper, errorProps, false, null);

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/protected").build());

      StepVerifier.create(entryPoint.commence(exchange, new BadCredentialsException("bad")))
          .verifyComplete();

      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
    }

    @Test
    @DisplayName("X-Requested-With: XMLHttpRequest (임의 Accept) → AJAX → 401 JSON")
    void XRequestedWith_AJAX_JSON() {
      KeycloakErrorProperties errorProps = new KeycloakErrorProperties();
      errorProps.setRedirectEnabled(true);
      errorProps.setAjaxReturnsJson(true);
      errorProps.setAuthenticationFailedRedirectUrl("/login");

      var entryPoint = new KeycloakServerAuthenticationEntryPoint(
          objectMapper, errorProps, false, null);

      // X-Requested-With만으로 AJAX 판정 — Accept는 */* 또는 없어도 무관
      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/protected")
              .header("X-Requested-With", "XMLHttpRequest")
              .accept(MediaType.ALL)
              .build());

      StepVerifier.create(entryPoint.commence(exchange, new BadCredentialsException("bad")))
          .verifyComplete();

      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("Bearer 요청은 redirect 모드여도 WWW-Authenticate: Bearer 응답")
    void Bearer_요청은_리다이렉트_아님() {
      KeycloakErrorProperties errorProps = new KeycloakErrorProperties();
      errorProps.setRedirectEnabled(true);

      var entryPoint = new KeycloakServerAuthenticationEntryPoint(
          objectMapper, errorProps, false, "realm");

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/api")
              .header(HttpHeaders.AUTHORIZATION, "Bearer tok")
              .build());

      StepVerifier.create(entryPoint.commence(exchange, new BadCredentialsException("bad")))
          .verifyComplete();

      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
      assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
          .startsWith("Bearer");
    }
  }
}
