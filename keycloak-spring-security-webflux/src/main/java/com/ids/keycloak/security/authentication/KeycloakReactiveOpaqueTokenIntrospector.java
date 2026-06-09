package com.ids.keycloak.security.authentication;

import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.util.KeycloakAuthorityExtractor;
import com.sd.KeycloakClient.dto.auth.KeycloakIntrospectResponse;
import com.sd.KeycloakClient.dto.user.KeycloakUserInfo;
import com.sd.KeycloakClient.factory.KeycloakClient;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector;
import reactor.core.publisher.Mono;

/**
 * Keycloak Introspect API를 통해 Bearer Token을 검증하고
 * {@link KeycloakPrincipal}을 생성하는 {@link ReactiveOpaqueTokenIntrospector} 구현체입니다.
 *
 * <p>servlet 모듈의 {@code KeycloakOpaqueTokenIntrospector}를 Reactive로 포팅합니다.
 * {@code authAsync().authenticationByIntrospect()} + {@code userAsync().getUserInfo()}를
 * Mono 체이닝으로 처리하며 {@code .block()} 없이 동작합니다.</p>
 */
@Slf4j
public class KeycloakReactiveOpaqueTokenIntrospector implements ReactiveOpaqueTokenIntrospector {

  private final KeycloakClient keycloakClient;
  private final String clientId;

  public KeycloakReactiveOpaqueTokenIntrospector(KeycloakClient keycloakClient, String clientId) {
    this.keycloakClient = keycloakClient;
    this.clientId = clientId;
  }

  /**
   * access_token을 Keycloak Introspect API로 검증하고 {@link KeycloakPrincipal}을 반환합니다.
   *
   * @param token access_token 문자열
   * @return {@link OAuth2AuthenticatedPrincipal}을 담은 Mono (실제로는 {@link KeycloakPrincipal})
   */
  @Override
  public Mono<OAuth2AuthenticatedPrincipal> introspect(String token) {
    log.debug("[BearerToken] Reactive Introspect 검증 시작.");

    return verifyTokenActive(token)
        .then(fetchUserInfo(token))
        .map(oidcUserInfo -> buildPrincipal(token, oidcUserInfo));
  }

  /**
   * Keycloak Introspect API를 호출하여 토큰이 active인지 확인합니다.
   */
  private Mono<Void> verifyTokenActive(String token) {
    return keycloakClient.authAsync().authenticationByIntrospect(token)
        .flatMap(response -> {
          int status = response.getStatus();

          if (status == 200) {
            KeycloakIntrospectResponse body = response.getBody().orElse(null);
            if (body == null) {
              return Mono.error(new BadOpaqueTokenException("Introspect 응답 본문이 없습니다."));
            }
            if (!body.getActive()) {
              log.debug("[BearerToken] 토큰이 비활성 상태입니다 (active=false).");
              return Mono.error(new BadOpaqueTokenException("토큰이 유효하지 않습니다."));
            }
            log.debug("[BearerToken] Introspect 검증 성공 (active=true).");
            return Mono.<Void>empty();
          }

          log.warn("[BearerToken] Introspect 검증 실패. 상태 코드: {}", status);
          return Mono.error(new BadOpaqueTokenException("토큰 검증 실패. 상태 코드: " + status));
        })
        .onErrorResume(
            e -> !(e instanceof BadOpaqueTokenException),
            e -> {
              log.error("[BearerToken] Keycloak 서버 통신 오류: {}", e.getMessage());
              return Mono.error(new BadOpaqueTokenException("인증 서버 통신 실패: " + e.getMessage()));
            });
  }

  /**
   * Keycloak UserInfo 엔드포인트를 비동기로 호출합니다.
   * UserInfo 조회 실패 시 null을 담은 Mono를 반환합니다.
   */
  private Mono<OidcUserInfo> fetchUserInfo(String accessToken) {
    return keycloakClient.userAsync().getUserInfo(accessToken)
        .flatMap(response -> {
          int status = response.getStatus();

          if (status == 200) {
            KeycloakUserInfo keycloakUserInfo = response.getBody().orElse(null);
            if (keycloakUserInfo != null) {
              log.debug("[BearerToken] UserInfo 조회 성공.");
              return Mono.just(convertToOidcUserInfo(keycloakUserInfo));
            }
          }

          log.warn("[BearerToken] UserInfo 조회 실패. 상태 코드: {}", status);
          return Mono.<OidcUserInfo>justOrEmpty(null);
        })
        .onErrorResume(e -> {
          log.warn("[BearerToken] UserInfo 조회 중 오류 발생: {}", e.getMessage());
          return Mono.justOrEmpty((OidcUserInfo) null);
        });
  }

  /**
   * UserInfo와 token으로 {@link KeycloakPrincipal}을 생성합니다.
   */
  private OAuth2AuthenticatedPrincipal buildPrincipal(String token, OidcUserInfo oidcUserInfo) {
    Map<String, Object> claims = (oidcUserInfo != null) ? oidcUserInfo.getClaims() : Map.of();
    Collection<GrantedAuthority> authorities = KeycloakAuthorityExtractor.extract(claims, clientId);

    String subject = extractSubject(claims);
    OidcIdToken oidcIdToken = new OidcIdToken(
        token, Instant.now(), null, Map.of("sub", subject));

    KeycloakPrincipal principal = new KeycloakPrincipal(subject, authorities, oidcIdToken, oidcUserInfo);
    log.debug("[BearerToken] Introspect 검증 성공. 사용자: {}", subject);
    return principal;
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

  private String extractSubject(Map<String, Object> claims) {
    Object sub = claims.get("sub");
    return sub != null ? sub.toString() : "unknown";
  }
}
