package com.ids.keycloak.security.authentication;

import com.ids.keycloak.security.exception.AuthenticationFailedException;
import com.ids.keycloak.security.exception.ConfigurationException;
import com.ids.keycloak.security.exception.IntrospectionFailedException;
import com.ids.keycloak.security.exception.UserInfoFetchException;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.util.JwtUtil;
import com.ids.keycloak.security.util.KeycloakAuthorityExtractor;
import com.sd.KeycloakClient.dto.KeycloakResponse;
import com.sd.KeycloakClient.dto.auth.KeycloakIntrospectResponse;
import com.sd.KeycloakClient.dto.user.KeycloakUserInfo;
import com.sd.KeycloakClient.factory.KeycloakClient;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.web.client.RestClientException;

/**
 * {@link KeycloakAuthentication}을 처리하는 {@link AuthenticationProvider} 구현체입니다.
 * <p>
 * 토큰 유효성 검증은 Keycloak Introspect API(온라인 검증)에 완전히 위임합니다.
 * 로컬에서는 서명/만료 검증 없이 토큰 클레임만 파싱하여 사용합니다.
 * </p>
 */
@Slf4j
public class KeycloakAuthenticationProvider implements AuthenticationProvider {

   private final KeycloakClient keycloakClient;
   private final String clientId;

   /**
    * UserInfo 실패 시 인증 실패 처리 여부.
    * 기본값 false = 기존 동작(빈 권한으로 인증 성공) 유지, 회귀 0.
    * keycloak.security.authentication.require-user-info=true 시 활성화됨.
    */
   private boolean requireUserInfo = false;

   public KeycloakAuthenticationProvider(KeycloakClient keycloakClient, String clientId) {
      this.keycloakClient = keycloakClient;
      this.clientId = clientId;
   }

   /**
    * UserInfo 실패 처리 방식을 설정합니다.
    * {@code KeycloakHttpConfigurer}에서 {@code keycloak.security.authentication.require-user-info} 값을 주입합니다.
    *
    * @param requireUserInfo true이면 UserInfo 실패 시 인증 실패로 처리
    */
   public void setRequireUserInfo(boolean requireUserInfo) {
      this.requireUserInfo = requireUserInfo;
   }

   /**
    * 토큰을 검증하고 인증 객체를 생성합니다.
    * 온라인 검증 실패 시 {@link IntrospectionFailedException}을 throw합니다.
    * 토큰 재발급은 Filter에서 담당합니다.
    *
    * @param authentication 인증 요청 객체
    * @return 인증된 Authentication 객체
    * @throws IntrospectionFailedException 온라인 검증 실패 시
    * @throws AuthenticationFailedException 그 외 인증 실패 시
    */
   @Override
   public Authentication authenticate(Authentication authentication) throws AuthenticationException {
      log.debug("[Provider] 인증 요청 시작: {}", authentication.getName());
      KeycloakAuthentication authRequest = (KeycloakAuthentication) authentication;

      String idTokenValue = authRequest.getIdToken();
      String accessTokenValue = authRequest.getAccessToken();

      log.debug("[Provider] Keycloak 온라인 검증 시도 (ID Token).");

      // 온라인 검증 (Keycloak Introspect) - ID Token으로 검증
      // 실패 시 IntrospectionFailedException이 throw되어 Filter에서 재발급 처리
      verifyTokenOnline(idTokenValue);

      log.debug("[Provider] 온라인 검증 성공. 인증된 객체 생성 시작.");
      return createAuthenticatedToken(idTokenValue, accessTokenValue);
   }

   /**
    * 검증된 토큰으로 인증 객체를 생성합니다.
    * Filter에서 토큰 재발급 후 직접 호출할 수 있도록 public으로 노출합니다.
    *
    * @param idTokenValue     ID Token
    * @param accessTokenValue Access Token
    * @return 인증된 Authentication 객체
    */
   public Authentication createAuthenticatedToken(String idTokenValue, String accessTokenValue) {
      // ID Token에서 subject(사용자 ID)와 클레임 추출
      Map<String, Object> idTokenClaims = JwtUtil.parseClaimsWithoutValidation(idTokenValue);
      String subject = JwtUtil.parseSubjectWithoutValidation(idTokenValue);

      // UserInfo 엔드포인트 호출
      OidcUserInfo oidcUserInfo = fetchUserInfo(accessTokenValue);

      // OidcIdToken 객체 생성
      OidcIdToken oidcIdToken = createOidcIdToken(idTokenValue, idTokenClaims);

      KeycloakPrincipal principal = createPrincipal(oidcIdToken, oidcUserInfo, subject);
      KeycloakAuthentication authenticatedToken = new KeycloakAuthentication(principal, idTokenValue, accessTokenValue, true);

      log.debug("[Provider] 최종 인증 객체 생성 완료: {}", principal.getName());
      return authenticatedToken;
   }

   /**
    * Keycloak UserInfo 엔드포인트를 호출하여 사용자 정보를 조회합니다.
    *
    * <p>모든 UserInfo 실패 경로(200+빈body, 401, 기타 상태코드, 네트워크 오류)에 대해
    * {@code requireUserInfo} 플래그를 동일하게 적용합니다.
    * <ul>
    *   <li>{@code requireUserInfo=false}(기본값): 모든 실패 시 null 반환(빈 권한으로 인증 성공, 기존 동작 복원)</li>
    *   <li>{@code requireUserInfo=true}: 모든 실패 시 {@link UserInfoFetchException} throw(인증 실패)</li>
    * </ul>
    * </p>
    *
    * @param accessToken Access Token
    * @return OidcUserInfo 객체 (requireUserInfo=false이고 실패 시 null)
    * @throws UserInfoFetchException requireUserInfo=true이고 UserInfo 조회 실패 시
    */
   private OidcUserInfo fetchUserInfo(String accessToken) {
      try {
         KeycloakResponse<KeycloakUserInfo> response = keycloakClient.user().getUserInfo(accessToken);
         int status = response.getStatus();

         switch (status) {
            case 200 -> {
               KeycloakUserInfo keycloakUserInfo = response.getBody().orElse(null);
               if (keycloakUserInfo != null) {
                  log.debug("[Provider] UserInfo 조회 성공.");
                  return convertToOidcUserInfo(keycloakUserInfo);
               }
               log.warn("[Provider] UserInfo 응답 본문이 비어있습니다.");
               return handleUserInfoFailure("UserInfo 응답 본문이 비어있습니다.");
            }
            case 401 -> {
               log.warn("[Provider] UserInfo 조회 실패 (401 Unauthorized).");
               return handleUserInfoFailure("UserInfo 조회 실패 (401 Unauthorized).");
            }
            default -> {
               log.warn("[Provider] UserInfo 조회 중 예상치 못한 응답. 상태 코드: {}", status);
               return handleUserInfoFailure("UserInfo 조회 중 예상치 못한 응답. 상태 코드: " + status);
            }
         }
      } catch (RestClientException e) {
         log.warn("[Provider] UserInfo 조회 중 오류 발생: {}", e.getMessage());
         return handleUserInfoFailure("UserInfo 조회 중 오류 발생: " + e.getMessage());
      }
   }

   /**
    * UserInfo 조회 실패를 {@code requireUserInfo} 플래그에 따라 처리합니다.
    *
    * <p>모든 UserInfo 실패 경로(200+빈body, 401, 기타 상태코드, 네트워크 오류)가
    * 이 메서드를 통해 일관되게 처리됩니다.</p>
    *
    * @param reason 실패 이유 메시지
    * @return null ({@code requireUserInfo=false}인 경우, 빈 권한으로 인증 성공)
    * @throws UserInfoFetchException {@code requireUserInfo=true}인 경우
    */
   private OidcUserInfo handleUserInfoFailure(String reason) {
      if (requireUserInfo) {
         log.warn("[Provider] require-user-info=true: UserInfo 실패를 인증 실패로 승격합니다. 사유: {}", reason);
         throw new UserInfoFetchException(reason);
      }
      log.debug("[Provider] require-user-info=false: UserInfo 실패 무시, 빈 권한으로 인증 성공. 사유: {}", reason);
      return null;
   }

   /**
    * KeycloakUserInfo를 OidcUserInfo로 변환합니다.
    *
    * @param keycloakUserInfo Keycloak UserInfo 응답
    * @return OidcUserInfo 객체
    */
   private OidcUserInfo convertToOidcUserInfo(KeycloakUserInfo keycloakUserInfo) {
      Map<String, Object> claims = new HashMap<>();

      // 고정 필드
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

      // 나머지 동적 필드들 (given_name, family_name, resource_access 등)
      claims.putAll(keycloakUserInfo.getOtherInfo());

      return new OidcUserInfo(claims);
   }

   /**
    * ID Token 문자열과 클레임에서 OidcIdToken 객체를 생성합니다.
    *
    * @param idTokenValue ID Token 문자열
    * @param claims       파싱된 클레임
    * @return OidcIdToken 객체
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
    * Keycloak Introspect API를 통해 토큰을 온라인으로 검증합니다.
    *
    * @param token 검증할 토큰 (ID Token)
    * @throws IntrospectionFailedException 토큰이 유효하지 않은 경우 (active=false 또는 401)
    * @throws ConfigurationException Keycloak 서버 오류 (500)
    * @throws AuthenticationFailedException 그 외 예상치 못한 응답
    */
   private void verifyTokenOnline(String token) {
      try {
         KeycloakResponse<KeycloakIntrospectResponse> response = keycloakClient.auth().authenticationByIntrospect(token);
         int status = response.getStatus();

         switch (status) {
            case 200 -> {
               // 응답 본문의 active 필드 확인 (중요!)
               KeycloakIntrospectResponse introspectResponse = response.getBody()
                   .orElseThrow(() -> new IntrospectionFailedException("온라인 검증 실패: 응답 본문이 없습니다."));

               if (!introspectResponse.getActive()) {
                  log.warn("[Provider] 온라인 검증 실패: 토큰이 비활성 상태입니다 (active=false).");
                  throw new IntrospectionFailedException("온라인 검증 실패: 토큰이 유효하지 않습니다.");
               }
               log.debug("[Provider] 온라인 검증 성공.");
            }
            case 401 -> {
               log.warn("[Provider] 온라인 검증 실패 (401 Unauthorized). 토큰 재발급을 시도합니다.");
               throw new IntrospectionFailedException("온라인 검증 실패: 토큰이 유효하지 않습니다.");
            }
            case 500 -> {
               log.error("[Provider] Keycloak 서버 오류 발생.");
               throw new ConfigurationException("Keycloak 서버에 오류가 발생했습니다.");
            }
            default -> {
               log.error("[Provider] 온라인 검증 중 예상치 못한 응답. 상태 코드: {}", status);
               throw new AuthenticationFailedException("온라인 검증 실패. 상태 코드: " + status);
            }
         }
      } catch (RestClientException e) {
         log.error("[Provider] Keycloak 서버와 통신 중 오류 발생: {}", e.getMessage());
         throw new ConfigurationException("Keycloak 서버와 통신할 수 없습니다: " + e.getMessage());
      }
   }

   /**
    * OidcIdToken과 OidcUserInfo에서 Principal 객체를 생성합니다.
    *
    * @param oidcIdToken  OidcIdToken 객체
    * @param oidcUserInfo OidcUserInfo 객체 (null 가능)
    * @param subject      사용자 ID (ID Token에서 추출)
    * @return Principal 객체
    */
   private KeycloakPrincipal createPrincipal(OidcIdToken oidcIdToken, OidcUserInfo oidcUserInfo, String subject) {
      // UserInfo에서 권한 추출 (UserInfo 조회 실패 시 빈 권한)
      Map<String, Object> claims = (oidcUserInfo != null) ? oidcUserInfo.getClaims() : Map.of();
      Collection<GrantedAuthority> authorities = KeycloakAuthorityExtractor.extract(claims, clientId);

      log.debug("[Provider] 사용자 '{}' Principal 생성 완료. 권한: {}", subject, authorities);

      return new KeycloakPrincipal(subject, authorities, oidcIdToken, oidcUserInfo);
   }

   @Override
   public boolean supports(Class<?> authentication) {
      return KeycloakAuthentication.class.isAssignableFrom(authentication);
   }
}