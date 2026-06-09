package com.ids.keycloak.security.filter;

import com.ids.keycloak.security.authentication.BackChannelLogoutAuthentication;
import com.ids.keycloak.security.authentication.ReactiveOidcBackChannelLogoutHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Back-Channel 로그아웃 엔드포인트({@code /logout/connect/back-channel/keycloak})를 처리하는 WebFilter입니다.
 *
 * <p>Keycloak이 POST 요청으로 {@code logout_token} 폼 파라미터를 전송하면,
 * 이 필터가 가로채어 {@link ReactiveOidcBackChannelLogoutHandler}로 위임합니다.</p>
 *
 * <p>이 필터가 처리하면 체인을 중단하고 직접 응답합니다(200/400).
 * 경로가 다르면 다음 필터로 투명하게 통과합니다.</p>
 *
 * <p><b>등록 조건:</b> {@code @ConditionalOnBean(ReactiveFindByIndexNameSessionRepository.class)}로
 * Spring Session Reactive가 활성화된 경우에만 등록됩니다.</p>
 */
@Slf4j
public class ReactiveBackChannelLogoutEndpointFilter implements WebFilter, Ordered {

  /** Keycloak Back-Channel 로그아웃 엔드포인트 경로 */
  public static final String BACK_CHANNEL_LOGOUT_PATH = "/logout/connect/back-channel/keycloak";

  private final ServerWebExchangeMatcher matcher;
  private final ReactiveOidcBackChannelLogoutHandler logoutHandler;

  public ReactiveBackChannelLogoutEndpointFilter(
      ReactiveOidcBackChannelLogoutHandler logoutHandler) {
    this.logoutHandler = logoutHandler;
    this.matcher = ServerWebExchangeMatchers
        .pathMatchers(HttpMethod.POST, BACK_CHANNEL_LOGOUT_PATH);
  }

  /**
   * Security 필터 체인 전에 실행되어 Back-Channel 요청을 우선 처리합니다.
   */
  @Override
  public int getOrder() {
    return Ordered.HIGHEST_PRECEDENCE + 5;
  }

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    return matcher.matches(exchange)
        .flatMap(result -> {
          if (!result.isMatch()) {
            return chain.filter(exchange);
          }
          log.debug("[BackChannelEndpoint] Back-Channel 로그아웃 요청 수신: {}",
              exchange.getRequest().getPath().value());
          return handleBackChannelLogout(exchange);
        });
  }

  /**
   * 폼 파라미터에서 logout_token을 추출하여 LogoutHandler로 위임합니다.
   */
  private Mono<Void> handleBackChannelLogout(ServerWebExchange exchange) {
    return exchange.getFormData()
        .flatMap(formData -> {
          String logoutTokenJwt = extractLogoutToken(formData);
          if (logoutTokenJwt == null || logoutTokenJwt.isBlank()) {
            log.warn("[BackChannelEndpoint] logout_token 파라미터 없음");
            return respondBadRequest(exchange, "Missing logout_token parameter");
          }

          log.debug("[BackChannelEndpoint] logout_token 수신, 세션 무효화 시작");

          // Authentication 객체에 logout_token JWT를 담아 전달
          BackChannelLogoutAuthentication authentication =
              new BackChannelLogoutAuthentication(logoutTokenJwt);

          org.springframework.security.web.server.WebFilterExchange webFilterExchange =
              new org.springframework.security.web.server.WebFilterExchange(
                  exchange,
                  webExchange -> Mono.empty() // chain — 사용하지 않음
              );

          return logoutHandler.logout(webFilterExchange, authentication);
        })
        .onErrorResume(e -> {
          log.error("[BackChannelEndpoint] Back-Channel 로그아웃 처리 중 오류: {}", e.getMessage(), e);
          return respondBadRequest(exchange, "Internal error: " + e.getMessage());
        });
  }

  private String extractLogoutToken(MultiValueMap<String, String> formData) {
    return formData.getFirst("logout_token");
  }

  private Mono<Void> respondBadRequest(ServerWebExchange exchange, String reason) {
    exchange.getResponse().setStatusCode(HttpStatus.BAD_REQUEST);
    exchange.getResponse().getHeaders().setContentType(MediaType.TEXT_PLAIN);
    byte[] bytes = reason.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    org.springframework.core.io.buffer.DataBuffer buffer =
        exchange.getResponse().bufferFactory().wrap(bytes);
    return exchange.getResponse().writeWith(Mono.just(buffer));
  }
}
