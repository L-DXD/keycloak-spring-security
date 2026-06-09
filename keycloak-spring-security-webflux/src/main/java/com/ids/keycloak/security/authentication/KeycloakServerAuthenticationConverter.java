package com.ids.keycloak.security.authentication;

import com.ids.keycloak.security.config.KeycloakCookieProperties;
import com.ids.keycloak.security.exception.AuthenticationFailedException;
import com.ids.keycloak.security.exception.RefreshTokenException;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.session.ReactiveSessionManager;
import com.ids.keycloak.security.util.ReactiveCookieUtil;
import com.sd.KeycloakClient.dto.auth.KeycloakTokenInfo;
import com.sd.KeycloakClient.factory.KeycloakClient;
import java.util.Collections;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

/**
 * {@link ServerWebExchange}에서 Keycloak 토큰을 추출하는 {@link ServerAuthenticationConverter} 구현체입니다.
 *
 * <p>servlet 모듈의 {@code KeycloakAuthenticationFilter} 토큰 추출 + 세션 연동 로직을 Reactive로 포팅합니다.</p>
 *
 * <p><b>처리 흐름:</b>
 * <ol>
 *   <li>쿠키 또는 WebSession에서 토큰 조회</li>
 *   <li>ID Token 없음 → Mono.empty() (인증 스킵)</li>
 *   <li>ID Token 있음 → 세션에서 Refresh Token 확인</li>
 *   <li>세션 없거나 Refresh Token 없음 → 쿠키 삭제 + Mono.empty()</li>
 *   <li>인증 요청 객체 생성 → {@link KeycloakReactiveAuthenticationManager}에 위임</li>
 *   <li>introspect 실패(TokenExpired 등) 시 → Refresh Token으로 재발급 → 응답 쿠키 갱신 후 재인증</li>
 * </ol>
 * </p>
 *
 * <p>Bearer, Basic, CREDENTIAL_LOGIN 방식은 다른 WebFilter/컨버터가 처리하므로 여기서 처리하지 않습니다.</p>
 */
@Slf4j
public class KeycloakServerAuthenticationConverter implements ServerAuthenticationConverter {

  /** 쿠키에 저장되는 ID Token 이름 */
  public static final String ID_TOKEN_COOKIE_NAME = "id_token";

  /** 쿠키에 저장되는 Access Token 이름 */
  public static final String ACCESS_TOKEN_COOKIE_NAME = "access_token";

  private final KeycloakReactiveAuthenticationManager authManager;
  private final KeycloakClient keycloakClient;
  private final ReactiveSessionManager sessionManager;
  private final KeycloakCookieProperties cookieProperties;

  public KeycloakServerAuthenticationConverter(
      KeycloakReactiveAuthenticationManager authManager,
      KeycloakClient keycloakClient,
      ReactiveSessionManager sessionManager,
      KeycloakCookieProperties cookieProperties) {
    this.authManager = authManager;
    this.keycloakClient = keycloakClient;
    this.sessionManager = sessionManager;
    this.cookieProperties = cookieProperties;
  }

  @Override
  public Mono<Authentication> convert(ServerWebExchange exchange) {
    return Mono.defer(() -> {
      ServerHttpRequest request = exchange.getRequest();

      String idToken = ReactiveCookieUtil.getCookieValue(request, ID_TOKEN_COOKIE_NAME).orElse(null);
      String accessToken = ReactiveCookieUtil.getCookieValue(request, ACCESS_TOKEN_COOKIE_NAME).orElse(null);

      if (idToken == null || idToken.isBlank()) {
        log.debug("[Converter] ID Token 쿠키 없음 — 인증 스킵.");
        return Mono.empty();
      }

      // WebSession을 비동기로 가져온 뒤, Refresh Token 확인
      return exchange.getSession()
          .flatMap(session -> handleWithSession(exchange, session, idToken, accessToken));
    });
  }

  /**
   * WebSession을 확보한 뒤 Refresh Token 기반 인증 처리를 수행합니다.
   */
  private Mono<Authentication> handleWithSession(
      ServerWebExchange exchange,
      WebSession session,
      String idToken,
      String accessToken) {

    Optional<String> refreshTokenOpt = sessionManager.getRefreshToken(session);

    if (refreshTokenOpt.isEmpty()) {
      log.debug("[Converter] WebSession에 Refresh Token 없음 — 쿠키 삭제 후 인증 스킵.");
      ReactiveCookieUtil.deleteAllTokenCookies(exchange.getResponse(), cookieProperties);
      return Mono.empty();
    }

    String refreshToken = refreshTokenOpt.get();
    log.debug("[Converter] WebSession에서 Refresh Token 로드 성공. 인증 요청 생성.");

    KeycloakPrincipal tempPrincipal = buildTempPrincipal(idToken);
    KeycloakAuthentication authRequest = new KeycloakAuthentication(
        tempPrincipal, idToken, accessToken, false);

    // authManager.authenticate() 내부에서 introspect 실패 시 예외 발생
    // 예외 발생 → refreshAndAuthenticate로 폴백
    return authManager.authenticate(authRequest)
        .onErrorResume(
            e -> isTokenExpiredOrInvalid(e),
            e -> {
              log.warn("[Converter] Introspect 실패, Refresh Token으로 재발급 시도. 원인: {}", e.getMessage());
              return refreshAndAuthenticate(exchange, session, refreshToken);
            })
        .cast(Authentication.class);
  }

  /**
   * Refresh Token으로 새 토큰을 발급받고 응답 쿠키를 갱신한 뒤 인증 객체를 반환합니다.
   */
  private Mono<Authentication> refreshAndAuthenticate(
      ServerWebExchange exchange,
      WebSession session,
      String refreshToken) {

    log.debug("[Converter] Keycloak에 토큰 재발급 요청...");

    return keycloakClient.authAsync().reissueToken(refreshToken)
        .flatMap(response -> {
          int status = response.getStatus();

          if (status == 200) {
            KeycloakTokenInfo newTokens = response.getBody()
                .orElseThrow(() -> new RefreshTokenException("토큰 재발급 실패: 응답 본문이 없습니다."));

            log.debug("[Converter] 토큰 재발급 성공. 세션 및 쿠키 업데이트.");

            // 응답 쿠키 갱신
            int expireTime = newTokens.getExpireTime();
            ReactiveCookieUtil.addTokenCookies(
                exchange.getResponse(),
                newTokens.getAccessToken(), expireTime,
                newTokens.getIdToken(), expireTime,
                cookieProperties);

            // H-N1: 새 Refresh Token 세션 저장 후 session.save()를 체인에 포함해 반드시 구독
            Mono<Void> saveSession = Mono.empty();
            if (newTokens.getRefreshToken() != null) {
              sessionManager.saveRefreshToken(session, newTokens.getRefreshToken());
              saveSession = session.save();
              log.debug("[Converter] 새 Refresh Token 세션 저장 예약.");
            }

            // session.save() 완료 후 UserInfo 조회 → 인증 객체 반환
            return saveSession
                .then(keycloakClient.userAsync().getUserInfo(newTokens.getAccessToken()))
                .flatMap(userInfoResponse -> {
                  org.springframework.security.oauth2.core.oidc.OidcUserInfo oidcUserInfo = null;
                  if (userInfoResponse.getStatus() == 200) {
                    com.sd.KeycloakClient.dto.user.KeycloakUserInfo keycloakUserInfo =
                        userInfoResponse.getBody().orElse(null);
                    if (keycloakUserInfo != null) {
                      oidcUserInfo = toOidcUserInfo(keycloakUserInfo);
                    }
                  }
                  Authentication auth = authManager.createAuthenticatedToken(
                      newTokens.getIdToken(), newTokens.getAccessToken(), oidcUserInfo);
                  return Mono.just(auth);
                })
                .onErrorResume(e -> {
                  log.warn("[Converter] 재발급 후 UserInfo 조회 실패, 빈 권한으로 진행: {}", e.getMessage());
                  Authentication auth = authManager.createAuthenticatedToken(
                      newTokens.getIdToken(), newTokens.getAccessToken(), null);
                  return Mono.just(auth);
                });

          } else if (status == 401) {
            log.warn("[Converter] Refresh Token 만료 또는 유효하지 않음 (401).");
            ReactiveCookieUtil.deleteAllTokenCookies(exchange.getResponse(), cookieProperties);
            return sessionManager.invalidateSession(session)
                .then(Mono.error(new RefreshTokenException("Refresh Token이 만료되었습니다.")));
          } else {
            log.error("[Converter] 토큰 재발급 중 예상치 못한 응답. 상태 코드: {}", status);
            return Mono.<Authentication>error(
                new AuthenticationFailedException("토큰 재발급 실패. 상태 코드: " + status));
          }
        })
        .onErrorResume(
            e -> !(e instanceof org.springframework.security.core.AuthenticationException)
                && !(e instanceof com.ids.keycloak.security.exception.KeycloakSecurityException),
            e -> {
              log.error("[Converter] 토큰 재발급 중 통신 오류: {}", e.getMessage());
              return Mono.error(new AuthenticationFailedException("Keycloak 통신 실패: " + e.getMessage()));
            });
  }

  /**
   * ID Token에서 subject를 파싱하여 임시 Principal을 생성합니다.
   * 실제 권한/UserInfo는 {@link KeycloakReactiveAuthenticationManager}에서 채워집니다.
   */
  private KeycloakPrincipal buildTempPrincipal(String idToken) {
    String subject = com.ids.keycloak.security.util.JwtUtil.parseSubjectWithoutValidation(idToken);
    if (subject == null || subject.isBlank()) {
      subject = "unknown";
    }
    return new KeycloakPrincipal(subject, Collections.emptyList(), null, null);
  }

  /**
   * 예외가 토큰 만료/유효하지 않음으로 인한 introspect 실패인지 판단합니다.
   * RefreshToken 재시도 대상 예외: IntrospectionFailed, TokenExpired, NullPointer, UserInfoFetch
   */
  private boolean isTokenExpiredOrInvalid(Throwable e) {
    return e instanceof com.ids.keycloak.security.exception.IntrospectionFailedException
        || e instanceof com.ids.keycloak.security.exception.TokenExpiredException
        || e instanceof com.ids.keycloak.security.exception.UserInfoFetchException
        || e instanceof NullPointerException;
  }

  /**
   * KeycloakUserInfo를 OidcUserInfo로 변환합니다 (M-1 재발급 후 권한 채우기용).
   */
  private org.springframework.security.oauth2.core.oidc.OidcUserInfo toOidcUserInfo(
      com.sd.KeycloakClient.dto.user.KeycloakUserInfo src) {
    java.util.Map<String, Object> claims = new java.util.HashMap<>();
    if (src.getSubject() != null) {
      claims.put("sub", src.getSubject());
    }
    if (src.getPreferredUsername() != null) {
      claims.put("preferred_username", src.getPreferredUsername());
    }
    if (src.getEmail() != null) {
      claims.put("email", src.getEmail());
    }
    if (src.getName() != null) {
      claims.put("name", src.getName());
    }
    if (src.getOtherInfo() != null) {
      claims.putAll(src.getOtherInfo());
    }
    return new org.springframework.security.oauth2.core.oidc.OidcUserInfo(claims);
  }
}
