package com.ids.keycloak.security.authentication;

import com.ids.keycloak.security.config.KeycloakCookieProperties;
import com.ids.keycloak.security.session.ReactiveSessionManager;
import com.ids.keycloak.security.util.ReactiveCookieUtil;
import com.sd.KeycloakClient.factory.KeycloakClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;
import reactor.core.publisher.Mono;

/**
 * 프론트채널 로그아웃 시 Keycloak 서버에 로그아웃을 요청하고,
 * WebSession을 무효화하고 토큰 쿠키를 삭제하는 {@link ServerLogoutHandler} 구현체입니다.
 *
 * <p>servlet 모듈의 {@code KeycloakLogoutHandler}를 Reactive로 포팅합니다.
 * WebSession 접근은 {@code exchange.getExchange().getSession()}(Mono)를 통해 비동기로 처리하며
 * {@code .block()} 없이 체이닝합니다.</p>
 */
@Slf4j
@RequiredArgsConstructor
public class KeycloakReactiveLogoutHandler implements ServerLogoutHandler {

  private final KeycloakClient keycloakClient;
  private final ReactiveSessionManager sessionManager;
  private final KeycloakCookieProperties cookieProperties;

  @Override
  public Mono<Void> logout(WebFilterExchange webFilterExchange, Authentication authentication) {
    log.debug("[LogoutHandler] 로그아웃 처리를 시작합니다.");

    return webFilterExchange.getExchange().getSession()
        .flatMap(session -> {
          // 1. Keycloak 서버에 로그아웃 요청 (Refresh Token으로)
          String refreshToken = sessionManager.getRefreshToken(session).orElse(null);
          Mono<Void> keycloakLogout = Mono.empty();

          if (refreshToken != null) {
            keycloakLogout = keycloakClient.authAsync().logout(refreshToken)
                .doOnSuccess(r -> log.debug("[LogoutHandler] Keycloak 서버 로그아웃 요청 완료."))
                .onErrorResume(e -> {
                  log.warn("[LogoutHandler] Keycloak 서버 로그아웃 요청 실패: {}", e.getMessage());
                  return Mono.empty();
                })
                .then();
          } else {
            log.debug("[LogoutHandler] 세션에 Refresh Token이 없습니다.");
          }

          // 2. WebSession 무효화
          Mono<Void> invalidate = sessionManager.invalidateSession(session);

          return keycloakLogout.then(invalidate);
        })
        .doOnSuccess(v -> {
          // 3. 모든 토큰 관련 쿠키 삭제
          ReactiveCookieUtil.deleteAllTokenCookies(
              webFilterExchange.getExchange().getResponse(), cookieProperties);
          log.debug("[LogoutHandler] 토큰 쿠키 삭제 완료. 로그아웃 처리 완료.");
        })
        .onErrorResume(e -> {
          log.warn("[LogoutHandler] 로그아웃 처리 중 오류 발생: {}", e.getMessage());
          ReactiveCookieUtil.deleteAllTokenCookies(
              webFilterExchange.getExchange().getResponse(), cookieProperties);
          return Mono.empty();
        });
  }
}
