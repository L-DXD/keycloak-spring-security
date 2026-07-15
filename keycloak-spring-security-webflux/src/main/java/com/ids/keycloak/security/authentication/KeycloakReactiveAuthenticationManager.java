package com.ids.keycloak.security.authentication;

import com.ids.keycloak.security.config.KeycloakRoleMappingProperties;
import com.ids.keycloak.security.exception.AuthenticationFailedException;
import com.ids.keycloak.security.exception.ConfigurationException;
import com.ids.keycloak.security.exception.IntrospectionFailedException;
import com.ids.keycloak.security.exception.TokenBindingException;
import com.ids.keycloak.security.exception.UserInfoFetchException;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.util.JwtUtil;
import com.ids.keycloak.security.util.KeycloakAuthorityExtractor;
import com.ids.keycloak.security.util.TokenBindingValidator;
import com.sd.KeycloakClient.dto.auth.KeycloakIntrospectResponse;
import com.sd.KeycloakClient.dto.user.KeycloakUserInfo;
import com.sd.KeycloakClient.factory.KeycloakClient;
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
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import reactor.core.publisher.Mono;

/**
 * Keycloak OIDC 인증을 처리하는 {@link ReactiveAuthenticationManager} 구현체입니다.
 *
 * <p>servlet 모듈의 {@code KeycloakAuthenticationProvider}를 Reactive Mono 체이닝으로 포팅합니다.
 * 토큰 유효성 검증은 Keycloak Introspect API(온라인 검증, 폐기/활성 여부 확인)와
 * {@link ReactiveJwtDecoder}(로컬 서명·iss·exp·nbf 검증) 두 단계로 이루어지며,
 * 블로킹 호출 없이 {@code authAsync()}/{@code userAsync()}/{@code ReactiveJwtDecoder} API만 사용합니다.</p>
 *
 * <p><b>보안 Advisory 1 대응:</b> ID Token은 {@link ReactiveJwtDecoder}로 서명 검증을 통과한 뒤에만
 * Principal 식별자(subject)로 사용하며, ID Token과 Access Token(UserInfo)이 동일 사용자·동일 Client에서
 * 발급되었는지({@link TokenBindingValidator}) 검증합니다. 하나라도 불일치하면
 * {@link TokenBindingException}이 발생해 인증에 실패합니다. (2.0.1 패치) JWT Access Token은
 * UserInfo 가용성과 무관하게 subject를 ID Token과 직접 비교합니다.</p>
 */
@Slf4j
public class KeycloakReactiveAuthenticationManager implements ReactiveAuthenticationManager {

  private final KeycloakClient keycloakClient;
  private final String clientId;
  private final ReactiveJwtDecoder jwtDecoder;

  /**
   * UserInfo 실패 시 인증 실패 처리 여부.
   * 기본값 false = 기존 동작(빈 권한으로 인증 성공) 유지, 회귀 0.
   * keycloak.security.authentication.require-user-info=true 시 활성화됨.
   */
  private boolean requireUserInfo = false;

  /**
   * Realm/Client 역할 → GrantedAuthority 매핑 전략 (보안 Advisory 7, CWE-863 대응).
   * 기본값은 realm/client 역할을 별도 네임스페이스로 분리하는 {@code SEPARATE_NAMESPACE}.
   */
  private KeycloakRoleMappingProperties roleMapping = new KeycloakRoleMappingProperties();

  /**
   * @param keycloakClient Keycloak Introspect/UserInfo 호출용 클라이언트
   * @param clientId       이 애플리케이션의 OIDC client-id (토큰 결합 검증에 사용)
   * @param jwtDecoder     ID Token/Access Token의 서명·iss·exp·nbf를 검증하는 {@link ReactiveJwtDecoder}
   *                       (Keycloak Realm JWKS 기반)
   */
  public KeycloakReactiveAuthenticationManager(
      KeycloakClient keycloakClient, String clientId, ReactiveJwtDecoder jwtDecoder) {
    this.keycloakClient = keycloakClient;
    this.clientId = clientId;
    this.jwtDecoder = jwtDecoder;
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
   * Realm/Client 역할 매핑 전략을 설정합니다.
   *
   * @param roleMapping Realm/Client 역할 네임스페이스 전략 (null이면 기본값 유지)
   */
  public void setRoleMapping(KeycloakRoleMappingProperties roleMapping) {
    this.roleMapping = roleMapping != null ? roleMapping : new KeycloakRoleMappingProperties();
  }

  /**
   * 토큰을 검증하고 인증 객체를 생성합니다.
   *
   * <p>처리 흐름:
   * <ol>
   *   <li>idToken으로 Keycloak Introspect 온라인 검증(폐기/활성 여부)</li>
   *   <li>accessToken으로 UserInfo 조회</li>
   *   <li>{@link #createAuthenticatedToken(String, String, OidcUserInfo)}에 위임 —
   *       ID Token 서명 검증(JwtDecoder), 토큰 결합 검증(sub/aud/azp), OidcIdToken 생성</li>
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
            .flatMap(oidcUserInfo -> createAuthenticatedToken(idTokenValue, accessTokenValue, oidcUserInfo))
            .switchIfEmpty(Mono.defer(
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
   * UserInfo 조회 후 직접 호출합니다. Refresh Token 재발급 경로에서도 이 메서드가 유일한 진입점이므로
   * (choke point), {@code authenticate()}를 우회해도 동일하게 검증됩니다.
   *
   * <p><b>보안 Advisory 1 대응 처리 순서:</b>
   * <ol>
   *   <li>ID Token을 {@link ReactiveJwtDecoder}로 디코딩(서명·iss·exp·nbf 검증) — 실패 시 {@link TokenBindingException}</li>
   *   <li>ID Token의 aud/azp가 이 애플리케이션의 client-id와 일치하는지 검증</li>
   *   <li>ID Token의 subject와 UserInfo의 subject가 일치하는지 검증</li>
   *   <li>Access Token이 JWT 형식이면 추가로 디코딩하여 azp와 subject(2.0.1 패치, ID Token과 직접
   *       비교)를 검증(Opaque면 로컬 결합 검증은 스킵)</li>
   * </ol>
   * 하나라도 실패하면 반환된 {@link Mono}가 {@link TokenBindingException}으로 에러 신호를 보냅니다.</p>
   *
   * @param idTokenValue     ID Token
   * @param accessTokenValue Access Token
   * @param oidcUserInfo     UserInfo (null 가능)
   * @return 인증된 {@link Authentication}을 담은 {@link Mono} (검증 실패 시 {@link TokenBindingException}로 에러)
   */
  public Mono<Authentication> createAuthenticatedToken(
      String idTokenValue, String accessTokenValue, OidcUserInfo oidcUserInfo) {
    return decodeIdToken(idTokenValue)
        .flatMap(idToken -> {
          // servlet KeycloakAuthenticationProvider와 동일한 순서로 정렬(일관성 목적, 보안 정책·결과는
          // 동일): ID Token 결합 검증 -> Subject 결합 검증 -> Access Token(JWT인 경우) azp/subject 검증.
          TokenBindingValidator.validateIdTokenBinding(idToken, clientId);
          TokenBindingValidator.validateSubjectBinding(
              idToken.getSubject(), oidcUserInfo != null ? oidcUserInfo.getSubject() : null);
          return validateAccessTokenIfJwt(accessTokenValue, idToken.getSubject())
              .then(Mono.fromCallable(
                  () -> buildAuthenticatedToken(idToken, idTokenValue, accessTokenValue, oidcUserInfo)));
        });
  }

  /**
   * ID Token을 {@link ReactiveJwtDecoder}로 디코딩합니다(서명·iss·exp·nbf 검증).
   *
   * @throws TokenBindingException 서명/클레임 검증 실패 시
   */
  private Mono<Jwt> decodeIdToken(String idTokenValue) {
    return jwtDecoder.decode(idTokenValue)
        .onErrorMap(JwtException.class, e -> {
          log.warn("[ReactiveAuthManager] ID Token 서명/클레임 검증 실패: {}", e.getMessage());
          return new TokenBindingException(
              "ID Token 서명 또는 클레임(iss/exp/nbf) 검증에 실패했습니다: " + e.getMessage(), e);
        });
  }

  /**
   * Access Token이 구조적으로 JWT 형식일 때만 추가로 디코딩하여 azp/subject 결합 검증을 수행합니다.
   *
   * <p><b>2.0.1 패치(외부 검토 High #1):</b> azp 검증({@link TokenBindingValidator#validateAccessTokenAzp})에
   * 이어 Access Token의 subject를 ID Token의 subject와 직접 비교합니다
   * ({@link TokenBindingValidator#validateAccessTokenSubject}). UserInfo 조회 실패
   * ({@code require-user-info=false})로 {@link TokenBindingValidator#validateSubjectBinding}이
   * 스킵되더라도, 이 직접 비교로 사용자 A의 ID Token과 사용자 B의 Access Token 조합(Principal=A,
   * 토큰=B)을 차단합니다.</p>
   *
   * <p><b>알려진 제약(Opaque Access Token):</b> servlet {@code KeycloakAuthenticationProvider}와
   * 동일하게, Access Token이 Opaque(비-JWT) 형식이면 로컬 aud/azp/subject 결합 검증을 수행할 수 없습니다
   * (Keycloak Introspect 응답이 {@code active} 여부만 노출하는 라이브러리 제약). 이 경우 UserInfo 200
   * 응답 + subject 일치 검증으로만 보호됩니다(기존 정책과 동일, 회귀 없음).</p>
   *
   * @param accessTokenValue Access Token
   * @param idTokenSubject   서명 검증이 완료된 ID Token에서 추출한 subject
   * @throws TokenBindingException Access Token이 JWT 구조인데 서명/클레임 검증에 실패했거나,
   *     azp/subject 결합 검증에 실패한 경우
   */
  private Mono<Void> validateAccessTokenIfJwt(String accessTokenValue, String idTokenSubject) {
    if (!JwtUtil.isStructurallyJwt(accessTokenValue)) {
      log.debug(
          "[ReactiveAuthManager] Access Token이 JWT 구조가 아님(Opaque 추정) — aud/azp/subject 로컬 결합 검증 스킵.");
      return Mono.empty();
    }
    return jwtDecoder.decode(accessTokenValue)
        .doOnNext(accessToken -> {
          TokenBindingValidator.validateAccessTokenAzp(accessToken, clientId);
          TokenBindingValidator.validateAccessTokenSubject(accessToken, idTokenSubject);
        })
        .onErrorMap(JwtException.class, e -> {
          log.warn("[ReactiveAuthManager] Access Token 서명/클레임 검증 실패: {}", e.getMessage());
          return new TokenBindingException(
              "Access Token 서명 또는 클레임 검증에 실패했습니다: " + e.getMessage(), e);
        })
        .then();
  }

  /**
   * 서명 검증 및 토큰 결합 검증(sub/aud/azp, {@link #createAuthenticatedToken}에서 선행 수행)이 모두
   * 끝난 ID Token, UserInfo로부터 최종 인증 객체를 생성합니다.
   */
  private Authentication buildAuthenticatedToken(
      Jwt idToken, String idTokenValue, String accessTokenValue, OidcUserInfo oidcUserInfo) {
    OidcIdToken oidcIdToken = createOidcIdToken(idTokenValue, idToken);
    KeycloakPrincipal principal = createPrincipal(oidcIdToken, oidcUserInfo, idToken.getSubject());

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
   * 서명 검증이 완료된 ID Token {@link Jwt}에서 OidcIdToken 객체를 생성합니다.
   */
  private OidcIdToken createOidcIdToken(String idTokenValue, Jwt idToken) {
    return new OidcIdToken(idTokenValue, idToken.getIssuedAt(), idToken.getExpiresAt(), idToken.getClaims());
  }

  /**
   * OidcIdToken과 OidcUserInfo에서 Principal 객체를 생성합니다.
   */
  private KeycloakPrincipal createPrincipal(
      OidcIdToken oidcIdToken, OidcUserInfo oidcUserInfo, String subject) {
    Map<String, Object> claims = (oidcUserInfo != null) ? oidcUserInfo.getClaims() : Map.of();
    Collection<GrantedAuthority> authorities =
        KeycloakAuthorityExtractor.extract(claims, clientId, roleMapping);

    log.debug(
        "[ReactiveAuthManager] 사용자 '{}' Principal 생성 완료. 권한: {}", subject, authorities);
    return new KeycloakPrincipal(subject, authorities, oidcIdToken, oidcUserInfo);
  }
}
