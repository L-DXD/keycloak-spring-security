package com.ids.keycloak.security.filter;

import com.ids.keycloak.security.config.KeycloakLoggingProperties;
import com.ids.keycloak.security.config.KeycloakSecurityProperties;
import com.ids.keycloak.security.logging.LoggingContextKeys;
import com.ids.keycloak.security.logging.LoggingValueSanitizer;
import com.ids.keycloak.security.logging.ReactiveLoggingContextAccessor;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

/**
 * WebFlux 환경에서 요청 메타데이터를 Reactor Context에 적재하는 로깅 필터입니다.
 *
 * <p>servlet 모듈의 {@code MdcRequestFilter}를 Reactive로 포팅합니다.
 * Reactor에서는 ThreadLocal MDC를 직접 사용할 수 없으므로, 로깅 컨텍스트를
 * <b>Reactor Context</b>에 저장하고 응답 헤더(X-Request-Id)로 traceId를 회신합니다.</p>
 *
 * <p><b>MDC 브릿지 전략 (최소 구현):</b>
 * Reactor Context → MDC 자동 브릿지는 {@code Hooks.onEachOperator} 또는
 * {@code CoreSubscriber} 데코레이터로 구현할 수 있으나 복잡도가 높습니다.
 * 현재는 다음만 보장합니다:
 * <ul>
 *   <li>traceId를 Reactor Context에 저장하고 응답 헤더로 회신</li>
 *   <li>응답 메트릭(status, durationMs) 토글 지원</li>
 *   <li>exclude-patterns 경로 제외</li>
 * </ul>
 * TODO: {@code reactor-tools} or MDC propagation 라이브러리 도입 시 전체 MDC 브릿지 구현 권장.
 * </p>
 *
 * @see ReactiveLoggingContextAccessor
 * @see ReactiveAuthLoggingFilter
 */
@Slf4j
@RequiredArgsConstructor
public class ReactiveLoggingFilter implements WebFilter, Ordered {

  private static final String X_REQUEST_ID_HEADER = "X-Request-Id";
  private static final String X_FORWARDED_FOR_HEADER = "X-Forwarded-For";
  private static final String USER_AGENT_HEADER = "User-Agent";
  private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();

  private final KeycloakSecurityProperties securityProperties;
  private final LoggingValueSanitizer sanitizer;

  @Override
  public int getOrder() {
    return Ordered.HIGHEST_PRECEDENCE + 10;
  }

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    if (isExcluded(exchange.getRequest())) {
      return chain.filter(exchange);
    }

    KeycloakLoggingProperties loggingProps = securityProperties.getLogging();
    long startTime = System.currentTimeMillis();

    // Reactor Context에 로깅 값을 적재
    Context loggingContext = buildLoggingContext(exchange, loggingProps);

    // traceId 응답 헤더 회신
    if (loggingProps.isIncludeTraceId() && loggingProps.isReturnTraceIdHeader()) {
      String traceId = ReactiveLoggingContextAccessor
          .getLoggingContext(loggingContext)
          .getOrDefault(LoggingContextKeys.TRACE_ID, "");
      if (!traceId.isBlank()) {
        exchange.getResponse().getHeaders().add(X_REQUEST_ID_HEADER, traceId);
      }
    }

    return chain.filter(exchange)
        .doFinally(signal -> {
          // 응답 메트릭 토글 — 기본 off
          if (loggingProps.isIncludeResponseMetrics()) {
            int status = exchange.getResponse().getStatusCode() != null
                ? exchange.getResponse().getStatusCode().value()
                : 0;
            long duration = System.currentTimeMillis() - startTime;
            log.info("[LoggingFilter] request completed — status={}, durationMs={}", status, duration);
          }
        })
        .contextWrite(ctx -> ctx.putAll(loggingContext));
  }

  /**
   * 요청 메타데이터를 Reactor Context 형태로 빌드합니다.
   */
  private Context buildLoggingContext(
      ServerWebExchange exchange, KeycloakLoggingProperties loggingProps) {

    ServerHttpRequest request = exchange.getRequest();
    Context context = Context.empty();

    // traceId
    if (loggingProps.isIncludeTraceId()) {
      String traceId = request.getHeaders().getFirst(X_REQUEST_ID_HEADER);
      if (traceId == null || traceId.isBlank()) {
        traceId = UUID.randomUUID().toString();
      }
      context = ReactiveLoggingContextAccessor.putValue(context, LoggingContextKeys.TRACE_ID, traceId);
    }

    // HTTP Method
    if (loggingProps.isIncludeHttpMethod()) {
      context = ReactiveLoggingContextAccessor.putValue(
          context, LoggingContextKeys.HTTP_METHOD, request.getMethod().name());
    }

    // Request URI
    if (loggingProps.isIncludeRequestUri()) {
      context = ReactiveLoggingContextAccessor.putValue(
          context, LoggingContextKeys.REQUEST_URI, request.getPath().value());
    }

    // Client IP
    if (loggingProps.isIncludeClientIp()) {
      context = ReactiveLoggingContextAccessor.putValue(
          context, LoggingContextKeys.CLIENT_IP, getClientIp(request));
    }

    // Query String: URL 디코딩 → 길이 제한 → 마스킹
    if (loggingProps.isIncludeQueryString()) {
      String rawQuery = request.getURI().getRawQuery();
      if (rawQuery != null) {
        String sanitized = sanitizer.sanitize(
            LoggingContextKeys.QUERY_STRING,
            truncate(decode(rawQuery), loggingProps.getMaxQueryLength()));
        context = ReactiveLoggingContextAccessor.putValue(
            context, LoggingContextKeys.QUERY_STRING, sanitized);
      }
    }

    // User-Agent: 길이 제한 → 마스킹
    if (loggingProps.isIncludeUserAgent()) {
      String userAgent = request.getHeaders().getFirst(USER_AGENT_HEADER);
      if (userAgent != null) {
        String sanitized = sanitizer.sanitize(
            LoggingContextKeys.USER_AGENT,
            truncate(userAgent, loggingProps.getMaxUserAgentLength()));
        context = ReactiveLoggingContextAccessor.putValue(
            context, LoggingContextKeys.USER_AGENT, sanitized);
      }
    }

    return context;
  }

  /**
   * exclude-patterns에 해당하는 경로인지 확인합니다.
   */
  private boolean isExcluded(ServerHttpRequest request) {
    List<String> excludePatterns = securityProperties.getLogging().getExcludePatterns();
    if (excludePatterns == null || excludePatterns.isEmpty()) {
      return false;
    }
    String path = request.getPath().value();
    for (String pattern : excludePatterns) {
      if (PATH_MATCHER.match(pattern, path)) {
        return true;
      }
    }
    return false;
  }

  private String getClientIp(ServerHttpRequest request) {
    String xff = request.getHeaders().getFirst(X_FORWARDED_FOR_HEADER);
    if (xff != null && !xff.isBlank()) {
      return xff.split(",")[0].trim();
    }
    String remoteAddress = request.getRemoteAddress() != null
        ? request.getRemoteAddress().getAddress().getHostAddress()
        : "unknown";
    return remoteAddress;
  }

  private String decode(String raw) {
    if (raw == null || raw.isEmpty()) {
      return raw;
    }
    try {
      return URLDecoder.decode(raw, StandardCharsets.UTF_8);
    } catch (IllegalArgumentException e) {
      return raw;
    }
  }

  private String truncate(String value, int maxLength) {
    if (value == null || value.length() <= maxLength) {
      return value;
    }
    return value.substring(0, maxLength) + "...[truncated]";
  }
}
