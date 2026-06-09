package com.ids.keycloak.security.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.ids.keycloak.security.config.KeycloakLoggingProperties;
import com.ids.keycloak.security.config.KeycloakSecurityProperties;
import com.ids.keycloak.security.logging.LoggingContextKeys;
import com.ids.keycloak.security.logging.ReactiveLoggingContextAccessor;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.util.context.Context;

/**
 * ReactiveAuthLoggingFilter 단위 테스트.
 * - H-1: 인증 완료 후 userId/username/sessionId가 Reactor Context에 실제로 적재되는지 검증.
 */
class ReactiveAuthLoggingFilterTest {

  private KeycloakSecurityProperties securityProperties;
  private ReactiveAuthLoggingFilter filter;

  @BeforeEach
  void setUp() {
    securityProperties = new KeycloakSecurityProperties();
    KeycloakLoggingProperties loggingProperties = securityProperties.getLogging();
    loggingProperties.setIncludeUserId(true);
    loggingProperties.setIncludeUsername(true);
    loggingProperties.setIncludeSessionId(true);
    filter = new ReactiveAuthLoggingFilter(securityProperties);
  }

  @Test
  @DisplayName("KeycloakPrincipal 인증 시 userId, username, sessionId가 Context에 적재된다")
  void KeycloakPrincipal_인증_컨텍스트_적재() {
    KeycloakPrincipal principal = buildKeycloakPrincipal("sub-abc", "user1", "sid-xyz");

    var authentication = new UsernamePasswordAuthenticationToken(
        principal, null, List.of());

    MockServerWebExchange exchange = MockServerWebExchange.from(
        MockServerHttpRequest.get("/test").build());

    AtomicReference<Map<String, String>> capturedContext = new AtomicReference<>();

    Mono<Void> result = filter.filter(exchange, serverWebExchange ->
        Mono.deferContextual(ctx -> {
          capturedContext.set(ReactiveLoggingContextAccessor.getLoggingContext(ctx));
          return Mono.empty();
        })
    ).contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));

    StepVerifier.create(result)
        .verifyComplete();

    Map<String, String> ctx = capturedContext.get();
    assertThat(ctx).isNotNull();
    assertThat(ctx.get(LoggingContextKeys.USER_ID)).isEqualTo("sub-abc");
    assertThat(ctx.get(LoggingContextKeys.USERNAME)).isEqualTo("user1");
    assertThat(ctx.get(LoggingContextKeys.SESSION_ID)).isEqualTo("sid-xyz");
  }

  @Test
  @DisplayName("인증 정보 없을 때 Context에 아무것도 추가되지 않는다")
  void 미인증_컨텍스트_빔() {
    MockServerWebExchange exchange = MockServerWebExchange.from(
        MockServerHttpRequest.get("/test").build());

    AtomicReference<Map<String, String>> capturedContext = new AtomicReference<>();

    Mono<Void> result = filter.filter(exchange, serverWebExchange ->
        Mono.deferContextual(ctx -> {
          capturedContext.set(ReactiveLoggingContextAccessor.getLoggingContext(ctx));
          return Mono.empty();
        })
    );

    StepVerifier.create(result)
        .verifyComplete();

    Map<String, String> ctx = capturedContext.get();
    assertThat(ctx.get(LoggingContextKeys.USER_ID)).isNull();
    assertThat(ctx.get(LoggingContextKeys.USERNAME)).isNull();
  }

  private KeycloakPrincipal buildKeycloakPrincipal(
      String subject, String username, String sid) {
    OidcIdToken idToken = new OidcIdToken(
        "id-tok",
        Instant.now(),
        Instant.now().plusSeconds(3600),
        Map.of("sub", subject, "sid", sid, "preferred_username", username));
    OidcUserInfo userInfo = new OidcUserInfo(
        Map.of("sub", subject, "preferred_username", username, "sid", sid));
    return new KeycloakPrincipal(subject, List.of(), idToken, userInfo);
  }
}
