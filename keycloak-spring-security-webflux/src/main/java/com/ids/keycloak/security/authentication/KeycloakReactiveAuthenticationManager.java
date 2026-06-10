package com.ids.keycloak.security.authentication;

import com.ids.keycloak.security.exception.AuthenticationFailedException;
import com.ids.keycloak.security.exception.ConfigurationException;
import com.ids.keycloak.security.exception.IntrospectionFailedException;
import com.ids.keycloak.security.exception.UserInfoFetchException;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.util.JwtUtil;
import com.ids.keycloak.security.util.KeycloakAuthorityExtractor;
import com.sd.KeycloakClient.dto.auth.KeycloakIntrospectResponse;
import com.sd.KeycloakClient.dto.user.KeycloakUserInfo;
import com.sd.KeycloakClient.factory.KeycloakClient;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import reactor.core.publisher.Mono;

/**
 * Keycloak OIDC 인증을 처리하는 {@link ReactiveAuthenticationManager} 구현체입니다.
 *
 * <p>servlet 모듈의 {@code KeycloakAuthenticationProvider}를 Reactive Mono 체이닝으로 포팅합니다.
 * 토큰 유효성 검증은 Keycloak Introspect API(온라인 검증)에 완전히 위임하며,
 * 블로킹 호출 없이 {@code authAsync()}/{@code userAsync()} API만 사용합니다.</p>
 */
@Slf4j
public class KeycloakReactiveAuthenticationManager implements ReactiveAuthenticationManager {

  private final KeycloakClient keycloakClient;
  private final String clientId;

  /**
   * UserInfo 실패 시 인증 실패 처리 여부.
   * 기본값 false = 기존 동작(빈 권한으로 인증 성공) 유지, 회귀 0.
   * keycloak.security.authentication.require-user-info=true 시 활성화됨.
   */
  private boolean requireUserInfo = false;

  public KeycloakReactiveAuthenticationManager(KeycloakClient keycloakClient, String clientId) {
    this.keycloakClient = keycloakClient;
    this.clientId = clientId;
  }

  /**
   * UserInfo 실패 처리 방식을 설정합니다.
   *
   * @param requireUserInfo true이면 UserInfo 실패 시 인증 실패로 처리
   */
  public void setRequireUserInfo(boolean requireUserInfo) {
    this.requireUserInfo = requireUserInfo;
  }

  /**
   * 토큰을 검증하고 인증 객체를 생성합니다.
   *
   * <p>처리 흐름:
   * <ol>
   *   <li>idToken으로 Keycloak Introspect 온라인 검증</li>
   *   <li>accessToken으로 UserInfo 조회</li>
   *   <li>JwtUtil로 idToken 클레임 파싱, OidcIdToken 생성</li>
   *   <li>KeycloakAuthorityExtractor로 권한 추출</li>
   *   <li>KeycloakPrincipal / KeycloakAuthentication(authenticated=true) 생성</li>
   * </ol>
   * </p>
   *
   * @param authentication 인증 요청 객체 ({@link KeycloakAuthentication})
   * @return 인증된 {@link Authentication}을 담은 {@link Mono}
   */
  @Override
  public Mono<Authentication> authenticate(Authentication authentication) {
    log.debug("[ReactiveAuthManager] 인증 요청 시작: {}", authentication.getName());

    KeycloakAuthentication authRequest = (KeycloakAuthentication) authentication;
    String idTokenValue = authRequest.getIdToken();
    String accessTokenValue = authRequest.getAccessToken();

    return verifyTokenOnline(idTokenValue)
        .then(Mono.defer(() -> fetchUserInfo(accessTokenValue)
            .map(oidcUserInfo -> createAuthenticatedToken(idTokenValue, accessTokenValue, oidcUserInfo))
            .switchIfEmpty(Mono.fromCallable(
                () -> createAuthenticatedToken(idTokenValue, accessTokenValue, null)))))
        .cast(Authentication.class)
        .onErrorResume(
            e -> !(e instanceof AuthenticationException)
                && !(e instanceof com.ids.keycloak.security.exception.KeycloakSecurityException),
            e -> {
              log.error("[ReactiveAuthManager] 예상치 못한 오류 발생: {}", e.getMessage(), e);
              return Mono.error(
                  new AuthenticationFailedException("인증 처리 중 오류가 발생했습니다: " + e.getMessage(), e));
            });
  }

  /**
   * 검증된 토큰으로 인증 객체를 생성합니다.
   * UserInfo 조회 후 직접 호출합니다.
   *
   * @param idTokenValue     ID Token
   * @param accessTokenValue Access Token
   * @param oidcUserInfo     UserInfo (null 가능)
   * @return 인증된 {@link Authentication} 객체
   */
  public Authentication createAuthenticatedToken(
      String idTokenValue, String accessTokenValue, OidcUserInfo oidcUserInfo) {
    Map<String, Object> idTokenClaims = JwtUtil.parseClaimsWithoutValidation(idTokenValue);
    String subject = JwtUtil.parseSubjectWithoutValidation(idTokenValue);

    OidcIdToken oidcIdToken = createOidcIdToken(idTokenValue, idTokenClaims);
    KeycloakPrincipal principal = createPrincipal(oidcIdToken, oidcUserInfo, subject);

    log.debug("[ReactiveAuthManager] 최종 인증 객체 생성 완료: {}", principal.getName());
    return new KeycloakAuthentication(principal, idTokenValue, accessTokenValue, true);
  }

  /**
   * Keycloak Introspect API를 통해 토큰을 온라인 검증합니다.
   *
   * <p>servlet의 동기 switch(status) 분기를 flatMap/map/onErrorResume으로 변환합니다.</p>
   */
  private Mono<Void> verifyTokenOnline(String token) {
    log.debug("[ReactiveAuthManager] Keycloak 온라인 검증 시도 (ID Token).");

    return keycloakClient.authAsync().authenticationByIntrospect(token)
        .flatMap(response -> {
          int status = response.getStatus();

          if (status == 200) {
            KeycloakIntrospectResponse introspectResponse =
                response.getBody().orElse(null);
            if (introspectResponse == null) {
              log.warn("[ReactiveAuthManager] 온라인 검증 실패: 응답 본문이 없습니다.");
              return Mono.error(
                  new IntrospectionFailedException("온라인 검증 실패: 응답 본문이 없습니다."));
            }
            if (!introspectResponse.getActive()) {
              log.warn("[ReactiveAuthManager] 온라인 검증 실패: 토큰이 비활성 상태입니다 (active=false).");
              return Mono.error(
                  new IntrospectionFailedException("온라인 검증 실패: 토큰이 유효하지 않습니다."));
            }
            log.debug("[ReactiveAuthManager] 온라인 검증 성공.");
            return Mono.<Void>empty();
          } else if (status == 401) {
            log.warn("[ReactiveAuthManager] 온라인 검증 실패 (401 Unauthorized).");
            return Mono.error(
                new IntrospectionFailedException("온라인 검증 실패: 토큰이 유효하지 않습니다."));
          } else if (status == 500) {
            log.error("[ReactiveAuthManager] Keycloak 서버 오류 발생.");
            return Mono.<Void>error(new ConfigurationException("Keycloak 서버에 오류가 발생했습니다."));
          } else {
            log.error("[ReactiveAuthManager] 온라인 검증 중 예상치 못한 응답. 상태 코드: {}", status);
            return Mono.<Void>error(
                new AuthenticationFailedException("온라인 검증 실패. 상태 코드: " + status));
          }
        })
        .onErrorResume(
            e -> !(e instanceof AuthenticationException)
                && !(e instanceof com.ids.keycloak.security.exception.KeycloakSecurityException),
            e -> {
              log.error("[ReactiveAuthManager] Keycloak 서버와 통신 중 오류 발생: {}", e.getMessage());
              return Mono.error(
                  new ConfigurationException(
                      "Keycloak 서버와 통신할 수 없습니다: " + e.getMessage()));
            });
  }

  /**
   * Keycloak UserInfo 엔드포인트를 비동기로 호출합니다.
   *
   * <p>모든 UserInfo 실패 경로(200+빈body, 401, 기타 상태코드, 네트워크 오류)에 대해
   * {@code requireUserInfo} 플래그를 동일하게 적용합니다(servlet N-1 수정과 동일 동작).
   * <ul>
   *   <li>{@code requireUserInfo=false}(기본값): 모든 실패 시 {@code Mono.empty()} 반환
   *       → switchIfEmpty에서 null UserInfo로 인증 성공(빈 권한)</li>
   *   <li>{@code requireUserInfo=true}: 모든 실패 시 {@link UserInfoFetchException} 에러
   *       → 인증 실패</li>
   * </ul>
   * </p>
   */
  private Mono<OidcUserInfo> fetchUserInfo(String accessToken) {
    return keycloakClient.userAsync().getUserInfo(accessToken)
        .flatMap(response -> {
          int status = response.getStatus();

          if (status == 200) {
            KeycloakUserInfo keycloakUserInfo = response.getBody().orElse(null);
            if (keycloakUserInfo != null) {
              log.debug("[ReactiveAuthManager] UserInfo 조회 성공.");
              return Mono.just(convertToOidcUserInfo(keycloakUserInfo));
            }
            log.warn("[ReactiveAuthManager] UserInfo 응답 본문이 비어있습니다.");
            return handleUserInfoFailureReactive("UserInfo 응답 본문이 비어있습니다.");
          } else if (status == 401) {
            log.warn("[ReactiveAuthManager] UserInfo 조회 실패 (401 Unauthorized).");
            return handleUserInfoFailureReactive("UserInfo 조회 실패 (401 Unauthorized).");
          } else {
            log.warn("[ReactiveAuthManager] UserInfo 조회 중 예상치 못한 응답. 상태 코드: {}", status);
            return handleUserInfoFailureReactive(
                "UserInfo 조회 중 예상치 못한 응답. 상태 코드: " + status);
          }
        })
        .onErrorResume(
            e -> !(e instanceof AuthenticationException)
                && !(e instanceof com.ids.keycloak.security.exception.KeycloakSecurityException),
            e -> {
              log.warn("[ReactiveAuthManager] UserInfo 조회 중 네트워크 오류 발생: {}", e.getMessage());
              return handleUserInfoFailureReactive("UserInfo 조회 중 오류 발생: " + e.getMessage());
            });
  }

  /**
   * UserInfo 조회 실패를 {@code requireUserInfo} 플래그에 따라 처리합니다(Reactive 버전).
   *
   * <p>servlet의 {@code handleUserInfoFailure}와 동일한 정책을 적용합니다.</p>
   *
   * @param reason 실패 이유 메시지
   * @return {@code Mono.empty()} ({@code requireUserInfo=false}인 경우, 빈 권한으로 인증 성공)
   *         또는 {@code Mono.error(UserInfoFetchException)} ({@code requireUserInfo=true}인 경우)
   */
  private Mono<OidcUserInfo> handleUserInfoFailureReactive(String reason) {
    if (requireUserInfo) {
      log.warn("[ReactiveAuthManager] require-user-info=true: UserInfo 실패를 인증 실패로 승격합니다. 사유: {}",
          reason);
      return Mono.error(new UserInfoFetchException(reason));
    }
    log.debug(
        "[ReactiveAuthManager] require-user-info=false: UserInfo 실패 무시, 빈 권한으로 인증 성공. 사유: {}",
        reason);
    return Mono.empty();
  }

  /**
   * KeycloakUserInfo를 OidcUserInfo로 변환합니다.
   */
  private OidcUserInfo convertToOidcUserInfo(KeycloakUserInfo keycloakUserInfo) {
    Map<String, Object> claims = new HashMap<>();

    if (keycloakUserInfo.getSubject() != null) {
      claims.put("sub", keycloakUserInfo.getSubject());
    }
    if (keycloakUserInfo.getPreferredUsername() != null) {
      claims.put("preferred_username", keycloakUserInfo.getPreferredUsername());
    }
    if (keycloakUserInfo.getEmail() != null) {
      claims.put("email", keycloakUserInfo.getEmail());
    }
    if (keycloakUserInfo.getName() != null) {
      claims.put("name", keycloakUserInfo.getName());
    }

    claims.putAll(keycloakUserInfo.getOtherInfo());
    return new OidcUserInfo(claims);
  }

  /**
   * ID Token 문자열과 클레임에서 OidcIdToken 객체를 생성합니다.
   */
  private OidcIdToken createOidcIdToken(String idTokenValue, Map<String, Object> claims) {
    Instant issuedAt = extractInstant(claims, "iat");
    Instant expiresAt = extractInstant(claims, "exp");
    return new OidcIdToken(idTokenValue, issuedAt, expiresAt, claims);
  }

  /**
   * 클레임에서 Instant 값을 추출합니다.
   */
  private Instant extractInstant(Map<String, Object> claims, String claimName) {
    Object value = claims.get(claimName);
    if (value instanceof Number) {
      return Instant.ofEpochSecond(((Number) value).longValue());
    }
    return null;
  }

  /**
   * OidcIdToken과 OidcUserInfo에서 Principal 객체를 생성합니다.
   */
  private KeycloakPrincipal createPrincipal(
      OidcIdToken oidcIdToken, OidcUserInfo oidcUserInfo, String subject) {
    Map<String, Object> claims = (oidcUserInfo != null) ? oidcUserInfo.getClaims() : Map.of();
    Collection<GrantedAuthority> authorities = KeycloakAuthorityExtractor.extract(claims, clientId);

    log.debug(
        "[ReactiveAuthManager] 사용자 '{}' Principal 생성 완료. 권한: {}", subject, authorities);
    return new KeycloakPrincipal(subject, authorities, oidcIdToken, oidcUserInfo);
  }
}
