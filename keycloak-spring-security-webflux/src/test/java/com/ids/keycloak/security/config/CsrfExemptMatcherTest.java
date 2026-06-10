package com.ids.keycloak.security.config;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.web.server.util.matcher.NegatedServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import reactor.test.StepVerifier;

/**
 * CSRF 면제 Matcher 단위 테스트.
 *
 * <p>{@link KeycloakWebFluxSecurityConfigurer}의 {@code configureCsrf} 내부에서
 * 구성되는 {@code NegatedServerWebExchangeMatcher(OrServerWebExchangeMatcher(면제경로들))} 로직을
 * 인라인으로 재현하여 검증합니다.</p>
 *
 * <p>CSRF 보호 = NOT(면제 대상) 공식 검증:
 * <ul>
 *   <li>면제 경로 → CSRF 검사 없음(notMatch → true: 보호 안 함)</li>
 *   <li>일반 경로 → CSRF 검사(match → true: 보호 함)</li>
 *   <li>Basic Auth 헤더 → CSRF 면제</li>
 * </ul>
 * </p>
 */
class CsrfExemptMatcherTest {

  /**
   * KeycloakWebFluxSecurityConfigurer.configureCsrf 와 동일한 matcher 구성 로직.
   *
   * @param exemptPaths          CSRF 면제 경로 목록
   * @param basicAuthExemptEnabled Basic Auth 헤더 면제 여부
   */
  private ServerWebExchangeMatcher buildCsrfMatcher(List<String> exemptPaths,
      boolean basicAuthExemptEnabled) {
    List<ServerWebExchangeMatcher> exemptMatchers = new ArrayList<>();
    for (String path : exemptPaths) {
      exemptMatchers.add(new PathPatternParserServerWebExchangeMatcher(path));
    }
    if (basicAuthExemptEnabled) {
      ServerWebExchangeMatcher basicAuthMatcher = exchange -> {
        String auth = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (auth != null && auth.startsWith("Basic ")) {
          return ServerWebExchangeMatcher.MatchResult.match();
        }
        return ServerWebExchangeMatcher.MatchResult.notMatch();
      };
      exemptMatchers.add(basicAuthMatcher);
    }
    // CSRF 보호 = NOT(면제 대상)
    return new NegatedServerWebExchangeMatcher(new OrServerWebExchangeMatcher(exemptMatchers));
  }

  private MockServerWebExchange exchange(String method, String path) {
    MockServerHttpRequest request = MockServerHttpRequest
        .method(method.equals("POST") ? HttpMethod.POST : HttpMethod.GET, path).build();
    return MockServerWebExchange.from(request);
  }

  private MockServerWebExchange exchangeWithHeader(String method, String path, String headerName,
      String headerValue) {
    MockServerHttpRequest request = MockServerHttpRequest
        .method(method.equals("POST") ? HttpMethod.POST : HttpMethod.GET, path)
        .header(headerName, headerValue).build();
    return MockServerWebExchange.from(request);
  }

  // ==========================================================================
  // 면제 경로 → CSRF 검사 없음 (matcher notMatch = 보호 안 함)
  // ==========================================================================

  @Nested
  class 면제_경로_CSRF_보호_없음 {

    @Test
    void 로그아웃_경로_CSRF_면제() {
      List<String> exemptPaths = List.of("/logout");
      ServerWebExchangeMatcher csrfMatcher = buildCsrfMatcher(exemptPaths, false);

      StepVerifier.create(csrfMatcher.matches(exchange("POST", "/logout")))
          .expectNextMatches(result -> !result.isMatch())
          .verifyComplete();
    }

    @Test
    void BackChannel_로그아웃_경로_CSRF_면제() {
      List<String> exemptPaths = List.of("/logout/connect/back-channel/**");
      ServerWebExchangeMatcher csrfMatcher = buildCsrfMatcher(exemptPaths, false);

      StepVerifier.create(
              csrfMatcher.matches(exchange("POST", "/logout/connect/back-channel/keycloak")))
          .expectNextMatches(result -> !result.isMatch())
          .verifyComplete();
    }

    @Test
    void Bearer_Token_엔드포인트_CSRF_면제() {
      List<String> exemptPaths = List.of("/api/token", "/api/refresh", "/api/logout");
      ServerWebExchangeMatcher csrfMatcher = buildCsrfMatcher(exemptPaths, false);

      StepVerifier.create(csrfMatcher.matches(exchange("POST", "/api/token")))
          .expectNextMatches(result -> !result.isMatch())
          .verifyComplete();

      StepVerifier.create(csrfMatcher.matches(exchange("POST", "/api/refresh")))
          .expectNextMatches(result -> !result.isMatch())
          .verifyComplete();
    }

    @Test
    void 사용자_지정_면제_경로_CSRF_면제() {
      List<String> exemptPaths = List.of("/webhook/**");
      ServerWebExchangeMatcher csrfMatcher = buildCsrfMatcher(exemptPaths, false);

      StepVerifier.create(csrfMatcher.matches(exchange("POST", "/webhook/event")))
          .expectNextMatches(result -> !result.isMatch())
          .verifyComplete();
    }
  }

  // ==========================================================================
  // 일반 경로 → CSRF 보호 적용 (matcher match = 보호 함)
  // ==========================================================================

  @Nested
  class 일반_경로_CSRF_보호_적용 {

    @Test
    void 일반_API_경로_CSRF_보호() {
      List<String> exemptPaths = List.of("/logout", "/logout/connect/back-channel/**");
      ServerWebExchangeMatcher csrfMatcher = buildCsrfMatcher(exemptPaths, false);

      StepVerifier.create(csrfMatcher.matches(exchange("POST", "/api/submit")))
          .expectNextMatches(ServerWebExchangeMatcher.MatchResult::isMatch)
          .verifyComplete();
    }

    @Test
    void 루트_경로_CSRF_보호() {
      List<String> exemptPaths = List.of("/logout");
      ServerWebExchangeMatcher csrfMatcher = buildCsrfMatcher(exemptPaths, false);

      StepVerifier.create(csrfMatcher.matches(exchange("POST", "/")))
          .expectNextMatches(ServerWebExchangeMatcher.MatchResult::isMatch)
          .verifyComplete();
    }
  }

  // ==========================================================================
  // H-4: /logout CSRF 면제는 Bearer Token 활성 시에만
  // ==========================================================================

  @Nested
  class H4_logout_CSRF_면제_조건 {

    @Test
    void bearerToken_비활성시_logout_경로는_CSRF_보호_적용됨() {
      // Bearer Token 비활성 → /logout이 면제 목록에 없음
      // KeycloakWebFluxSecurityConfigurer.configureCsrf: bearerToken.isEnabled()==false 이면
      // /logout을 ignorePaths에 추가하지 않는다.
      List<String> exemptPaths = List.of("/logout/connect/back-channel/keycloak");
      ServerWebExchangeMatcher csrfMatcher = buildCsrfMatcher(exemptPaths, false);

      // POST /logout → CSRF 보호 적용 (match=true)
      StepVerifier.create(csrfMatcher.matches(exchange("POST", "/logout")))
          .expectNextMatches(ServerWebExchangeMatcher.MatchResult::isMatch)
          .verifyComplete();
    }

    @Test
    void bearerToken_활성시_logout_경로는_CSRF_면제됨() {
      // Bearer Token 활성 → /logout이 면제 목록에 포함
      List<String> exemptPaths = List.of("/auth/token", "/auth/refresh", "/auth/logout", "/logout",
          "/logout/connect/back-channel/keycloak");
      ServerWebExchangeMatcher csrfMatcher = buildCsrfMatcher(exemptPaths, false);

      // POST /logout → CSRF 면제 (match=false)
      StepVerifier.create(csrfMatcher.matches(exchange("POST", "/logout")))
          .expectNextMatches(result -> !result.isMatch())
          .verifyComplete();
    }

    @Test
    void bearerToken_비활성시_back_channel_경로는_여전히_CSRF_면제() {
      // /logout/connect/back-channel/keycloak 은 항상 면제
      List<String> exemptPaths = List.of("/logout/connect/back-channel/keycloak");
      ServerWebExchangeMatcher csrfMatcher = buildCsrfMatcher(exemptPaths, false);

      StepVerifier.create(
              csrfMatcher.matches(exchange("POST", "/logout/connect/back-channel/keycloak")))
          .expectNextMatches(result -> !result.isMatch())
          .verifyComplete();
    }
  }

  // ==========================================================================
  // Basic Auth 헤더 면제
  // ==========================================================================

  @Nested
  class BasicAuth_헤더_면제 {

    @Test
    void Authorization_Basic_헤더_있으면_CSRF_면제() {
      List<String> exemptPaths = List.of("/logout");
      ServerWebExchangeMatcher csrfMatcher = buildCsrfMatcher(exemptPaths, true);

      MockServerWebExchange ex = exchangeWithHeader("POST", "/api/resource",
          "Authorization", "Basic dXNlcjpwYXNz");

      StepVerifier.create(csrfMatcher.matches(ex))
          .expectNextMatches(result -> !result.isMatch())
          .verifyComplete();
    }

    @Test
    void Authorization_Bearer_헤더는_CSRF_보호_적용() {
      List<String> exemptPaths = List.of("/logout");
      ServerWebExchangeMatcher csrfMatcher = buildCsrfMatcher(exemptPaths, true);

      MockServerWebExchange ex = exchangeWithHeader("POST", "/api/resource",
          "Authorization", "Bearer some.token.here");

      StepVerifier.create(csrfMatcher.matches(ex))
          .expectNextMatches(ServerWebExchangeMatcher.MatchResult::isMatch)
          .verifyComplete();
    }

    @Test
    void Authorization_헤더_없으면_일반_경로_CSRF_보호() {
      List<String> exemptPaths = List.of("/logout");
      ServerWebExchangeMatcher csrfMatcher = buildCsrfMatcher(exemptPaths, true);

      StepVerifier.create(csrfMatcher.matches(exchange("POST", "/api/resource")))
          .expectNextMatches(ServerWebExchangeMatcher.MatchResult::isMatch)
          .verifyComplete();
    }

    @Test
    void basicAuth_비활성화시_Basic_헤더_있어도_CSRF_보호() {
      List<String> exemptPaths = List.of("/logout");
      // basicAuthExemptEnabled=false
      ServerWebExchangeMatcher csrfMatcher = buildCsrfMatcher(exemptPaths, false);

      MockServerWebExchange ex = exchangeWithHeader("POST", "/api/resource",
          "Authorization", "Basic dXNlcjpwYXNz");

      StepVerifier.create(csrfMatcher.matches(ex))
          .expectNextMatches(ServerWebExchangeMatcher.MatchResult::isMatch)
          .verifyComplete();
    }
  }
}
