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
 * - API 모드(redirectEnabled=false) 기본 + AJAX/명시적 JSON → JSON 401
 * - API 모드(redirectEnabled=false) 기본 + 비-AJAX(브라우저) → OAuth2 로그인으로 302 리다이렉트 (C-1)
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
    @DisplayName("명시적 JSON Accept 요청 → 401 JSON 응답")
    void JSON_Accept_요청_401_JSON() {
      var entryPoint = new KeycloakServerAuthenticationEntryPoint(objectMapper);

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/api/resource")
              .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
              .build());

      StepVerifier.create(entryPoint.commence(exchange, new BadCredentialsException("bad")))
          .verifyComplete();

      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("H-B: Accept: text/html을 명시한 브라우저 요청 → 기본적으로 OAuth2 로그인으로 리다이렉트")
    void Accept_text_html을_명시한_브라우저_요청은_OAuth2_로그인으로_리다이렉트한다() {
      var entryPoint = new KeycloakServerAuthenticationEntryPoint(objectMapper);

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/api/resource")
              .accept(MediaType.TEXT_HTML, MediaType.parseMediaType("application/xhtml+xml"), MediaType.ALL)
              .build());

      StepVerifier.create(entryPoint.commence(exchange, new BadCredentialsException("bad")))
          .verifyComplete();

      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
      assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.LOCATION))
          .isEqualTo("/oauth2/authorization/keycloak");
    }

    @Test
    @DisplayName("H-B 회귀 수정: Accept 헤더가 없는 요청 → 302 대신 401 JSON")
    void Accept_헤더가_없는_요청은_401_JSON을_반환한다() {
      // curl 기본 요청·서버간 호출처럼 Accept 헤더가 없는 요청은 "AJAX가 아니면 브라우저"가 아니라
      // acceptsHtmlExplicitly("Accept: text/html을 실제로 명시했을 때만 브라우저") 기준으로
      // 판정되어 302 리다이렉트 대신 401 JSON을 받아야 한다(2.0.2 대비 breaking 회귀 수정).
      var entryPoint = new KeycloakServerAuthenticationEntryPoint(objectMapper);

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/api/resource").build());

      StepVerifier.create(entryPoint.commence(exchange, new BadCredentialsException("bad")))
          .verifyComplete();

      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("H-B 회귀 수정: Accept: */* 단독 요청도 401 JSON")
    void Accept_wildcard_단독_요청도_401_JSON을_반환한다() {
      var entryPoint = new KeycloakServerAuthenticationEntryPoint(objectMapper);

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/api/resource")
              .accept(MediaType.ALL)
              .build());

      StepVerifier.create(entryPoint.commence(exchange, new BadCredentialsException("bad")))
          .verifyComplete();

      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("C-B: oauth2LoginAvailable=false면 무한 302 루프 대신 401 JSON을 반환한다")
    void oauth2LoginAvailable_false면_리다이렉트_대신_401_JSON을_반환한다() {
      // oauth2Login이 실제로 등록되지 않았다면 /oauth2/authorization/{registrationId}를 처리할
      // 필터 자체가 없어, 리다이렉트를 보내면 그 경로도 미인증으로 남아 이 EntryPoint가 다시
      // 호출되는 무한 302 루프가 된다 — 이 경우 리다이렉트 대신 401 JSON을 반환해야 한다.
      var entryPoint = new KeycloakServerAuthenticationEntryPoint(
          objectMapper, new KeycloakErrorProperties(), false, null, false);

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/api/resource")
              .accept(MediaType.TEXT_HTML, MediaType.ALL)
              .build());

      StepVerifier.create(entryPoint.commence(exchange, new BadCredentialsException("bad")))
          .verifyComplete();

      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
      assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.LOCATION)).isNull();
    }

    @Test
    @DisplayName("C-B: authorization 엔드포인트 자체 요청은 다시 리다이렉트되지 않는다(자기참조 가드)")
    void authorization_엔드포인트_자체_요청은_다시_리다이렉트되지_않는다() {
      var entryPoint = new KeycloakServerAuthenticationEntryPoint(objectMapper);

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/oauth2/authorization/keycloak")
              .accept(MediaType.TEXT_HTML, MediaType.ALL)
              .build());

      StepVerifier.create(entryPoint.commence(exchange, new BadCredentialsException("bad")))
          .verifyComplete();

      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
      assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.LOCATION)).isNull();
    }

    @Test
    @DisplayName("H-A: context-path가 있으면 리다이렉트 URL에 prefix가 붙는다")
    void context_path가_있으면_리다이렉트_URL에_prefix가_붙는다() {
      var entryPoint = new KeycloakServerAuthenticationEntryPoint(objectMapper);

      MockServerWebExchange exchange = MockServerWebExchange.from(
          MockServerHttpRequest.get("/myapp/api/resource")
              .contextPath("/myapp")
              .accept(MediaType.TEXT_HTML, MediaType.ALL)
              .build());

      StepVerifier.create(entryPoint.commence(exchange, new BadCredentialsException("bad")))
          .verifyComplete();

      assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
      assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.LOCATION))
          .isEqualTo("/myapp/oauth2/authorization/keycloak");
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
