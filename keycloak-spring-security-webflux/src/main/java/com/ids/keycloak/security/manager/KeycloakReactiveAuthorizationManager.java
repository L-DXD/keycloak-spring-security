package com.ids.keycloak.security.manager;

import com.ids.keycloak.security.authentication.AccessTokenHolder;
import com.sd.KeycloakClient.dto.auth.KeycloakAuthorizationResult;
import com.sd.KeycloakClient.factory.KeycloakClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import reactor.core.publisher.Mono;

/**
 * Keycloak Authorization Services를 사용하여 HTTP 요청에 대한 인가를 수행하는
 * {@link ReactiveAuthorizationManager} 구현체입니다.
 *
 * <p>servlet 모듈의 {@code KeycloakAuthorizationManager}를 Reactive로 포팅합니다.
 * {@code authAsync().authorization(accessToken, endpoint, method)}를 Mono로 호출하며
 * {@code .block()} 없이 비동기 체이닝으로 결과를 처리합니다.</p>
 *
 * <p>지원 인증 타입:
 * <ul>
 *   <li>{@link AccessTokenHolder} — KeycloakAuthentication, BasicAuthenticationToken</li>
 *   <li>{@link BearerTokenAuthentication} — Spring Security OAuth2 Resource Server</li>
 * </ul>
 * </p>
 */
@Slf4j
@RequiredArgsConstructor
public class KeycloakReactiveAuthorizationManager
    implements ReactiveAuthorizationManager<AuthorizationContext> {

  private final KeycloakClient keycloakClient;

  /**
   * 현재 인증된 사용자가 요청한 HTTP 리소스에 접근할 수 있는지 Keycloak에 인가 요청을 보냅니다.
   *
   * @param authentication 인증 정보 Mono
   * @param context        인가 컨텍스트 (HTTP 메서드, 엔드포인트 포함)
   * @return {@link AuthorizationDecision}을 담은 Mono
   */
  @Override
  public Mono<AuthorizationDecision> check(
      Mono<Authentication> authentication,
      AuthorizationContext context) {

    ServerHttpRequest request = context.getExchange().getRequest();
    String method = request.getMethod().name();
    String endpoint = request.getPath().value();

    log.debug("[ReactiveAuthorization] 인가 요청 수신: {} {}", method, endpoint);

    return authentication
        .filter(auth -> auth != null && auth.isAuthenticated())
        .flatMap(auth -> reactor.core.publisher.Mono.justOrEmpty(extractAccessToken(auth)))
        .flatMap(accessToken -> {
          log.debug("[ReactiveAuthorization] Keycloak에 인가 요청...");
          return keycloakClient.authAsync().authorization(accessToken, endpoint, method)
              .map(response -> {
                KeycloakAuthorizationResult result = response.getBody().orElse(null);
                if (result == null) {
                  log.warn("[ReactiveAuthorization] Keycloak 인가 응답 본문 없음. 거부 처리: {} {}",
                      method, endpoint);
                  return new AuthorizationDecision(false);
                }
                boolean granted = result.isGranted();
                log.debug("[ReactiveAuthorization] Keycloak 인가 결과: {} - {} {}",
                    granted ? "허용" : "거부", method, endpoint);
                return new AuthorizationDecision(granted);
              })
              .onErrorResume(e -> {
                log.warn("[ReactiveAuthorization] Keycloak 인가 요청 실패 (통신 오류). 거부 처리: {} {} - {}",
                    method, endpoint, e.getMessage());
                return Mono.just(new AuthorizationDecision(false));
              });
        })
        .defaultIfEmpty(new AuthorizationDecision(false))
        .doOnNext(decision -> {
          if (!decision.isGranted()) {
            log.warn("[ReactiveAuthorization] 미인증 또는 지원하지 않는 인증 타입 — 거부: {} {}",
                method, endpoint);
          }
        });
  }

  /**
   * 인증 객체에서 Access Token을 추출합니다.
   */
  private String extractAccessToken(Authentication auth) {
    if (auth instanceof AccessTokenHolder holder) {
      log.debug("[ReactiveAuthorization] AccessTokenHolder 인증 타입: {}",
          auth.getClass().getSimpleName());
      return holder.getAccessToken();
    } else if (auth instanceof BearerTokenAuthentication bearer) {
      log.debug("[ReactiveAuthorization] BearerTokenAuthentication 인증 타입");
      return bearer.getToken().getTokenValue();
    }
    log.warn("[ReactiveAuthorization] 지원하지 않는 인증 타입: {}", auth.getClass().getSimpleName());
    return null;
  }
}
