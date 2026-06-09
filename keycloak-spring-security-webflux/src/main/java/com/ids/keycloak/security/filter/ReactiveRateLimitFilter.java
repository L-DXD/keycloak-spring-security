package com.ids.keycloak.security.filter;

import com.ids.keycloak.security.config.KeycloakRateLimitProperties;
import com.ids.keycloak.security.config.RateLimitKeyStrategy;
import com.ids.keycloak.security.ratelimit.AuthenticationEventLogger;
import com.ids.keycloak.security.ratelimit.RateLimiter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * 인증 시도에 대한 Rate Limiting을 수행하는 WebFilter입니다.
 *
 * <p>servlet 모듈의 {@code RateLimitFilter}를 Reactive WebFilter로 포팅합니다.
 * core의 {@link RateLimiter} 인터페이스를 재사용하며,
 * 토큰 발급 API와 Basic Auth 요청에 대해 브루트포스 공격을 방지합니다.</p>
 *
 * <p><b>동작 방식:</b>
 * <ol>
 *   <li>요청 전: 차단 여부 확인 (카운트 증가 없음)</li>
 *   <li>차단 중이면 즉시 429 Too Many Requests 반환</li>
 *   <li>차단 아니면 다음 필터로 위임</li>
 *   <li>응답 후: 401/403이면 실패 기록 (post-filter)</li>
 * </ol>
 * </p>
 *
 * <p>Reactive에서는 응답 상태를 post-filter에서 확인하기 어렵습니다.
 * 따라서 doFinally로 응답 완료 시점에 상태를 확인하여 실패를 기록합니다.</p>
 */
@Slf4j
public class ReactiveRateLimitFilter implements WebFilter, Ordered {

  private static final String AUTHORIZATION_HEADER = "Authorization";
  private static final String BASIC_PREFIX = "Basic ";
  private static final String X_FORWARDED_FOR_HEADER = "X-Forwarded-For";
  private static final byte[] RATE_LIMIT_ERROR_BODY =
      "{\"error\":\"rate_limit_exceeded\",\"error_description\":\"Too many authentication attempts. Please try again later.\"}"
          .getBytes(StandardCharsets.UTF_8);

  private final RateLimiter rateLimiter;
  private final KeycloakRateLimitProperties properties;
  private final List<String> rateLimitPaths;

  public ReactiveRateLimitFilter(
      RateLimiter rateLimiter,
      KeycloakRateLimitProperties properties,
      List<String> rateLimitPaths) {
    this.rateLimiter = rateLimiter;
    this.properties = properties;
    this.rateLimitPaths = rateLimitPaths;
  }

  @Override
  public int getOrder() {
    // BasicAuth 필터보다 앞에 위치 (차단된 요청은 인증 시도 자체를 하지 않음)
    return Ordered.HIGHEST_PRECEDENCE + 50;
  }

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    if (!shouldApply(exchange)) {
      return chain.filter(exchange);
    }

    String clientIp = getClientIp(exchange);
    String username = extractUsername(exchange);
    String authMethod = detectAuthMethod(exchange);
    RateLimitKeyStrategy strategy = properties.getKeyStrategy();

    // 1단계: 차단 여부만 확인 (카운트 증가 없음)
    if (isBlocked(strategy, clientIp, username)) {
      String key = buildPrimaryKey(strategy, clientIp, username);
      long retryAfter = rateLimiter.getRetryAfterSeconds(key);

      AuthenticationEventLogger.logRateLimited(authMethod, clientIp, username);
      return writeRateLimitResponse(exchange.getResponse(), retryAfter);
    }

    // 2단계: 다음 필터 실행 후 응답 상태에 따라 실패 기록
    return chain.filter(exchange)
        .doFinally(signal -> {
          if (exchange.getResponse().getStatusCode() != null) {
            int status = exchange.getResponse().getStatusCode().value();
            if (status == 401 || status == 403) {
              recordFailure(strategy, clientIp, username);
            }
          }
        });
  }

  /**
   * Rate Limit을 적용해야 하는 요청인지 확인합니다.
   */
  private boolean shouldApply(ServerWebExchange exchange) {
    String requestPath = exchange.getRequest().getPath().value();

    // Token API 경로 체크
    for (String path : rateLimitPaths) {
      if (requestPath.equals(path)) {
        return true;
      }
    }

    // Basic Auth 포함 설정 시, Basic 헤더가 있는 요청도 대상
    if (properties.isIncludeBasicAuth()) {
      String authHeader = exchange.getRequest().getHeaders().getFirst(AUTHORIZATION_HEADER);
      if (authHeader != null && authHeader.startsWith(BASIC_PREFIX)) {
        return true;
      }
    }

    return false;
  }

  /**
   * 429 Too Many Requests 응답을 작성합니다.
   */
  private Mono<Void> writeRateLimitResponse(ServerHttpResponse response, long retryAfter) {
    response.setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
    response.getHeaders().add("Retry-After", String.valueOf(retryAfter));
    response.getHeaders().add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
    DataBuffer buffer = response.bufferFactory().wrap(RATE_LIMIT_ERROR_BODY);
    return response.writeWith(Mono.just(buffer));
  }

  /**
   * Rate Limit 키 전략에 따라 차단 여부를 판단합니다.
   */
  private boolean isBlocked(RateLimitKeyStrategy strategy, String clientIp, String username) {
    return switch (strategy) {
      case IP -> rateLimiter.isBlocked("ip:" + clientIp);
      case USERNAME -> {
        if (username != null) {
          yield rateLimiter.isBlocked("user:" + username);
        }
        yield rateLimiter.isBlocked("ip:" + clientIp);
      }
      case IP_AND_USERNAME -> {
        if (rateLimiter.isBlocked("ip:" + clientIp)) {
          yield true;
        }
        if (username != null) {
          yield rateLimiter.isBlocked("user:" + username);
        }
        yield false;
      }
    };
  }

  /**
   * Rate Limit 키 전략에 따라 인증 실패를 기록합니다.
   */
  private void recordFailure(RateLimitKeyStrategy strategy, String clientIp, String username) {
    switch (strategy) {
      case IP -> rateLimiter.recordFailure("ip:" + clientIp);
      case USERNAME -> {
        if (username != null) {
          rateLimiter.recordFailure("user:" + username);
        } else {
          rateLimiter.recordFailure("ip:" + clientIp);
        }
      }
      case IP_AND_USERNAME -> {
        rateLimiter.recordFailure("ip:" + clientIp);
        if (username != null) {
          rateLimiter.recordFailure("user:" + username);
        }
      }
    }
  }

  /**
   * Retry-After 계산을 위한 기본 키를 반환합니다.
   */
  private String buildPrimaryKey(RateLimitKeyStrategy strategy, String clientIp, String username) {
    return switch (strategy) {
      case USERNAME -> username != null ? "user:" + username : "ip:" + clientIp;
      default -> "ip:" + clientIp;
    };
  }

  /**
   * Basic Auth 헤더에서 username을 추출합니다.
   */
  private String extractUsername(ServerWebExchange exchange) {
    String authHeader = exchange.getRequest().getHeaders().getFirst(AUTHORIZATION_HEADER);
    if (authHeader != null && authHeader.startsWith(BASIC_PREFIX)) {
      try {
        String base64Credentials = authHeader.substring(BASIC_PREFIX.length()).trim();
        String credentials = new String(
            Base64.getDecoder().decode(base64Credentials), StandardCharsets.UTF_8);
        int colonIndex = credentials.indexOf(':');
        if (colonIndex > 0) {
          return credentials.substring(0, colonIndex);
        }
      } catch (IllegalArgumentException e) {
        // Base64 디코딩 실패 시 무시
      }
    }
    return null;
  }

  private String detectAuthMethod(ServerWebExchange exchange) {
    String authHeader = exchange.getRequest().getHeaders().getFirst(AUTHORIZATION_HEADER);
    if (authHeader != null && authHeader.startsWith(BASIC_PREFIX)) {
      return "BASIC";
    }
    return "TOKEN_API";
  }

  private String getClientIp(ServerWebExchange exchange) {
    String xff = exchange.getRequest().getHeaders().getFirst(X_FORWARDED_FOR_HEADER);
    if (xff != null && !xff.isBlank()) {
      return xff.split(",")[0].trim();
    }
    return exchange.getRequest().getRemoteAddress() != null
        ? exchange.getRequest().getRemoteAddress().getAddress().getHostAddress()
        : "unknown";
  }
}
