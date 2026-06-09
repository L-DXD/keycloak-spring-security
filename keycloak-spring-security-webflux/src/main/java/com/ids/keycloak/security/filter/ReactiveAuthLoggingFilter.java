package com.ids.keycloak.security.filter;

import com.ids.keycloak.security.config.KeycloakLoggingProperties;
import com.ids.keycloak.security.config.KeycloakSecurityProperties;
import com.ids.keycloak.security.logging.LoggingContextKeys;
import com.ids.keycloak.security.logging.ReactiveLoggingContextAccessor;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

/**
 * 인증 완료 후 사용자 정보를 Reactor Context(MDC 브릿지 포함)에 추가하는 WebFilter입니다.
 *
 * <p>servlet 모듈의 {@code MdcAuthenticationFilter}를 Reactive로 포팅합니다.
 * SecurityContext를 ReactiveSecurityContextHolder에서 비동기로 조회하여
 * userId, username, sessionId를 Reactor Context에 추가합니다.</p>
 *
 * <p><b>구현 패턴:</b> chain.filter(exchange) 완료 후 contextWrite 하는 방식은
 * 이미 downstream 에서 SecurityContext가 소비된 이후라 userId를 적재할 수 없습니다.
 * 대신 chain.filter(exchange)를 구독하기 전에 {@code ReactiveSecurityContextHolder.getContext()}를
 * 실제 구독하여 Reactor Context에 userId/username/sessionId를 주입합니다.</p>
 *
 * <p>MDC 정리는 {@link ReactiveLoggingFilter}에서 doFinally 시점에 수행됩니다.</p>
 */
@Slf4j
@RequiredArgsConstructor
public class ReactiveAuthLoggingFilter implements WebFilter, Ordered {

  private final KeycloakSecurityProperties securityProperties;

  @Override
  public int getOrder() {
    // ReactiveLoggingFilter(HIGHEST_PRECEDENCE+10) 이후, 인증 필터 이후에 위치
    return Ordered.HIGHEST_PRECEDENCE + 200;
  }

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    KeycloakLoggingProperties loggingProps = securityProperties.getLogging();

    // ReactiveSecurityContextHolder에서 인증 정보를 실제 구독하여 Reactor Context에 적재한 뒤
    // chain.filter(exchange)를 실행합니다.
    return ReactiveSecurityContextHolder.getContext()
        .map(SecurityContext::getAuthentication)
        .filter(auth -> auth != null && auth.isAuthenticated()
            && !(auth instanceof AnonymousAuthenticationToken))
        .map(auth -> buildAuthContextFromAuth(auth, loggingProps))
        .defaultIfEmpty(Context.empty())
        .flatMap(authCtx ->
            chain.filter(exchange)
                .contextWrite(ctx -> mergeContext(ctx, authCtx)));
  }

  /**
   * Authentication에서 로깅 컨텍스트(userId, username, sessionId)를 Reactor Context로 추출합니다.
   */
  private Context buildAuthContextFromAuth(
      Authentication auth, KeycloakLoggingProperties loggingProps) {

    Object principal = auth.getPrincipal();
    Map<String, Object> attributes = extractAttributes(principal, auth);

    Context ctx = Context.empty();

    if (attributes == null) {
      // 속성을 파싱할 수 없는 경우 — auth.getName()으로 username만 적재
      if (loggingProps.isIncludeUsername()) {
        ctx = ReactiveLoggingContextAccessor.putValue(
            ctx, LoggingContextKeys.USERNAME, auth.getName());
      }
      return ctx;
    }

    if (loggingProps.isIncludeUserId()) {
      Object sub = attributes.get("sub");
      if (sub != null) {
        ctx = ReactiveLoggingContextAccessor.putValue(
            ctx, LoggingContextKeys.USER_ID, sub.toString());
      }
    }
    if (loggingProps.isIncludeUsername()) {
      Object username = attributes.get("preferred_username");
      if (username != null) {
        ctx = ReactiveLoggingContextAccessor.putValue(
            ctx, LoggingContextKeys.USERNAME, username.toString());
      }
    }
    if (loggingProps.isIncludeSessionId()) {
      Object sid = attributes.get("sid");
      if (sid != null) {
        ctx = ReactiveLoggingContextAccessor.putValue(
            ctx, LoggingContextKeys.SESSION_ID, sid.toString());
      }
    }
    return ctx;
  }

  /**
   * 기존 Reactor Context에 인증 컨텍스트를 병합합니다.
   */
  private Context mergeContext(Context existing, Context authCtx) {
    if (authCtx.isEmpty()) {
      return existing;
    }
    // authCtx의 KEYCLOAK_LOGGING_CONTEXT 맵을 existing에 병합
    Object loggingMap = authCtx.getOrDefault(ReactiveLoggingContextAccessor.CONTEXT_KEY, null);
    if (loggingMap == null) {
      return existing;
    }
    return existing.put(ReactiveLoggingContextAccessor.CONTEXT_KEY, loggingMap);
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> extractAttributes(Object principal, Authentication auth) {
    if (principal instanceof KeycloakPrincipal keycloakPrincipal) {
      return keycloakPrincipal.getAttributes();
    } else if (principal instanceof OidcUser oidcUser) {
      return oidcUser.getAttributes();
    } else if (principal instanceof Jwt jwt) {
      return (Map<String, Object>) jwt.getClaims();
    }
    return null;
  }
}
