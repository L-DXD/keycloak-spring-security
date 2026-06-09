package com.ids.keycloak.security.config;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import reactor.test.StepVerifier;

/**
 * SecurityMatcher (Reactive) include/exclude 패턴 매칭 동작 테스트.
 *
 * <p>{@link KeycloakWebFluxConstants} 및 {@link PathPatternParserServerWebExchangeMatcher}를 조합한
 * 실제 Reactive 매처 동작을 {@code MockServerWebExchange}로 검증합니다.</p>
 *
 * <p>buildSecurityMatcher 로직은 webflux-starter에 있으므로
 * 여기서는 동일 로직을 인라인으로 재현하여 검증합니다.</p>
 */
class SecurityMatcherTest {

  /**
   * KeycloakWebFluxAutoConfiguration.buildSecurityMatcher 와 동일한 로직.
   */
  private ServerWebExchangeMatcher buildMatcher(List<String> includes, List<String> excludes) {
    ServerWebExchangeMatcher includeMatcher = toOrMatcher(includes);

    if (excludes == null || excludes.isEmpty()) {
      return includeMatcher;
    }

    ServerWebExchangeMatcher excludeMatcher = toOrMatcher(excludes);
    return exchange -> includeMatcher.matches(exchange)
        .flatMap(includeResult -> {
          if (!includeResult.isMatch()) {
            return ServerWebExchangeMatcher.MatchResult.notMatch();
          }
          return excludeMatcher.matches(exchange)
              .flatMap(excludeResult ->
                  excludeResult.isMatch()
                      ? ServerWebExchangeMatcher.MatchResult.notMatch()
                      : ServerWebExchangeMatcher.MatchResult.match());
        });
  }

  private ServerWebExchangeMatcher toOrMatcher(List<String> patterns) {
    if (patterns == null || patterns.isEmpty()) {
      return exchange -> ServerWebExchangeMatchers.anyExchange().matches(exchange);
    }
    if (patterns.size() == 1) {
      return new PathPatternParserServerWebExchangeMatcher(patterns.get(0));
    }
    List<ServerWebExchangeMatcher> matchers = new ArrayList<>();
    for (String pattern : patterns) {
      matchers.add(new PathPatternParserServerWebExchangeMatcher(pattern));
    }
    return ServerWebExchangeMatchers.matchers(matchers.toArray(new ServerWebExchangeMatcher[0]));
  }

  private MockServerWebExchange exchange(String path) {
    MockServerHttpRequest request = MockServerHttpRequest.get(path).build();
    return MockServerWebExchange.from(request);
  }

  // ==========================================================================
  // include 패턴만 (exclude 없음)
  // ==========================================================================

  @Nested
  class include_패턴 {

    @Test
    void include_패턴이_없으면_모든_경로_매칭() {
      ServerWebExchangeMatcher matcher = buildMatcher(List.of(), List.of());

      StepVerifier.create(matcher.matches(exchange("/any/path")))
          .expectNextMatches(ServerWebExchangeMatcher.MatchResult::isMatch)
          .verifyComplete();
    }

    @Test
    void include_패턴에_매칭되는_경로_match() {
      ServerWebExchangeMatcher matcher = buildMatcher(List.of("/api/**"), List.of());

      StepVerifier.create(matcher.matches(exchange("/api/users")))
          .expectNextMatches(ServerWebExchangeMatcher.MatchResult::isMatch)
          .verifyComplete();
    }

    @Test
    void include_패턴에_매칭되지_않는_경로_notMatch() {
      ServerWebExchangeMatcher matcher = buildMatcher(List.of("/api/**"), List.of());

      StepVerifier.create(matcher.matches(exchange("/health")))
          .expectNextMatches(result -> !result.isMatch())
          .verifyComplete();
    }

    @Test
    void 여러_include_패턴_중_하나_매칭되면_match() {
      ServerWebExchangeMatcher matcher = buildMatcher(
          List.of("/api/**", "/v2/**"), List.of());

      StepVerifier.create(matcher.matches(exchange("/v2/items")))
          .expectNextMatches(ServerWebExchangeMatcher.MatchResult::isMatch)
          .verifyComplete();
    }
  }

  // ==========================================================================
  // exclude 패턴 (include + exclude)
  // ==========================================================================

  @Nested
  class exclude_패턴 {

    @Test
    void include_매칭이지만_exclude_매칭이면_notMatch() {
      ServerWebExchangeMatcher matcher = buildMatcher(List.of("/**"), List.of("/actuator/**"));

      StepVerifier.create(matcher.matches(exchange("/actuator/health")))
          .expectNextMatches(result -> !result.isMatch())
          .verifyComplete();
    }

    @Test
    void include_매칭이고_exclude_미매칭이면_match() {
      ServerWebExchangeMatcher matcher = buildMatcher(List.of("/**"), List.of("/actuator/**"));

      StepVerifier.create(matcher.matches(exchange("/api/users")))
          .expectNextMatches(ServerWebExchangeMatcher.MatchResult::isMatch)
          .verifyComplete();
    }

    @Test
    void include_미매칭이면_exclude_와_무관하게_notMatch() {
      ServerWebExchangeMatcher matcher = buildMatcher(
          List.of("/api/**"), List.of("/api/public/**"));

      StepVerifier.create(matcher.matches(exchange("/other")))
          .expectNextMatches(result -> !result.isMatch())
          .verifyComplete();
    }

    @Test
    void logout_경로_exclude_설정시_notMatch() {
      // /actuator/** 는 보안 체인에서 제외하는 대표 패턴
      ServerWebExchangeMatcher matcher = buildMatcher(
          List.of("/**"), List.of("/actuator/**", "/public/**"));

      StepVerifier.create(matcher.matches(exchange("/public/info")))
          .expectNextMatches(result -> !result.isMatch())
          .verifyComplete();
    }
  }
}
