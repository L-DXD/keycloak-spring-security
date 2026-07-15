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
import com.sd.KeycloakClient.dto.KeycloakResponse;
import com.sd.KeycloakClient.dto.auth.KeycloakIntrospectResponse;
import com.sd.KeycloakClient.dto.user.KeycloakUserInfo;
import com.sd.KeycloakClient.factory.KeycloakClient;
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
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.client.RestClientException;

/**
 * {@link KeycloakAuthentication}을 처리하는 {@link AuthenticationProvider} 구현체입니다.
 * <p>
 * 토큰 유효성 검증은 Keycloak Introspect API(온라인 검증, 폐기/활성 여부 확인)와
 * {@link JwtDecoder}(로컬 서명·iss·exp·nbf 검증) 두 단계로 이루어집니다.
 * </p>
 * <p><b>보안 Advisory 1 대응:</b> ID Token은 {@link JwtDecoder}로 서명 검증을 통과한 뒤에만 Principal
 * 식별자(subject)로 사용하며, ID Token과 Access Token(UserInfo)이 동일 사용자·동일 Client에서
 * 발급되었는지({@link TokenBindingValidator}) 검증합니다. 하나라도 불일치하면
 * {@link TokenBindingException}이 발생해 인증에 실패합니다. (2.0.1 패치) JWT Access Token은
 * UserInfo 가용성과 무관하게 subject를 ID Token과 직접 비교합니다.</p>
 */
@Slf4j
public class KeycloakAuthenticationProvider implements AuthenticationProvider {

   private final KeycloakClient keycloakClient;
   private final String clientId;
   private final JwtDecoder jwtDecoder;

   /**
    * UserInfo 실패 시 인증 실패 처리 여부.
    * 기본값 false = 기존 동작(빈 권한으로 인증 성공) 유지, 회귀 0.
    * keycloak.security.authentication.require-user-info=true 시 활성화됨.
    */
   private boolean requireUserInfo = false;

   /**
    * Realm/Client 역할 → GrantedAuthority 매핑 전략 (보안 Advisory 7, CWE-863 대응).
    * 기본값은 realm/client 역할을 별도 네임스페이스로 분리하는 {@code SEPARATE_NAMESPACE}.
    * {@code KeycloakHttpConfigurer}/AutoConfiguration에서
    * {@code keycloak.security.role-mapping} 설정을 주입합니다.
    */
   private KeycloakRoleMappingProperties roleMapping = new KeycloakRoleMappingProperties();

   /**
    * @param keycloakClient Keycloak Introspect/UserInfo 호출용 클라이언트
    * @param clientId       이 애플리케이션의 OIDC client-id (토큰 결합 검증에 사용)
    * @param jwtDecoder     ID Token/Access Token의 서명·iss·exp·nbf를 검증하는 {@link JwtDecoder}
    *                       (Keycloak Realm JWKS 기반)
    */
   public KeycloakAuthenticationProvider(KeycloakClient keycloakClient, String clientId, JwtDecoder jwtDecoder) {
      this.keycloakClient = keycloakClient;
      this.clientId = clientId;
      this.jwtDecoder = jwtDecoder;
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
    * Realm/Client 역할 매핑 전략을 설정합니다.
    * {@code KeycloakHttpConfigurer}에서 {@code keycloak.security.role-mapping} 값을 주입합니다.
    *
    * @param roleMapping Realm/Client 역할 네임스페이스 전략 (null이면 기본값 유지)
    */
   public void setRoleMapping(KeycloakRoleMappingProperties roleMapping) {
      this.roleMapping = roleMapping != null ? roleMapping : new KeycloakRoleMappingProperties();
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
    * Filter에서 토큰 재발급(Refresh) 후에도 직접 호출하므로, 이 메서드 자체가 검증 파이프라인의
    * 단일 진입점(choke point)입니다 — {@code authenticate()}를 우회해도 동일하게 검증됩니다.
    *
    * <p><b>보안 Advisory 1 대응 처리 순서:</b>
    * <ol>
    *   <li>ID Token을 {@link JwtDecoder}로 디코딩(서명·iss·exp·nbf 검증) — 실패 시 {@link TokenBindingException}</li>
    *   <li>Access Token으로 UserInfo 조회(기존 로직)</li>
    *   <li>ID Token의 aud/azp가 이 애플리케이션의 client-id와 일치하는지 검증</li>
    *   <li>ID Token의 subject와 UserInfo의 subject가 일치하는지 검증</li>
    *   <li>Access Token이 JWT 형식이면 추가로 디코딩하여 azp와 subject(2.0.1 패치, ID Token과 직접
    *       비교)를 검증(Opaque면 로컬 결합 검증은 스킵)</li>
    * </ol>
    * 하나라도 실패하면 {@link TokenBindingException}이 발생해 인증이 실패합니다(SecurityContext 미생성).</p>
    *
    * @param idTokenValue     ID Token
    * @param accessTokenValue Access Token
    * @return 인증된 Authentication 객체
    * @throws TokenBindingException ID Token 검증 실패 또는 토큰 결합 검증 실패 시
    */
   public Authentication createAuthenticatedToken(String idTokenValue, String accessTokenValue) {
      // Advisory 1 STEP 1: 서명 검증을 통과한 ID Token만 사용 (미검증 파싱 금지)
      Jwt idToken = decodeIdToken(idTokenValue);

      // UserInfo 엔드포인트 호출 (기존 로직 유지)
      OidcUserInfo oidcUserInfo = fetchUserInfo(accessTokenValue);

      // Advisory 1 STEP 2: 토큰 결합 검증 — 하나라도 불일치하면 TokenBindingException
      TokenBindingValidator.validateIdTokenBinding(idToken, clientId);
      TokenBindingValidator.validateSubjectBinding(
          idToken.getSubject(), oidcUserInfo != null ? oidcUserInfo.getSubject() : null);
      validateAccessTokenIfJwt(accessTokenValue, idToken.getSubject());

      OidcIdToken oidcIdToken = createOidcIdToken(idTokenValue, idToken);
      KeycloakPrincipal principal = createPrincipal(oidcIdToken, oidcUserInfo, idToken.getSubject());
      KeycloakAuthentication authenticatedToken = new KeycloakAuthentication(principal, idTokenValue, accessTokenValue, true);

      log.debug("[Provider] 최종 인증 객체 생성 완료: {}", principal.getName());
      return authenticatedToken;
   }

   /**
    * ID Token을 {@link JwtDecoder}로 디코딩합니다(서명·iss·exp·nbf 검증).
    *
    * @throws TokenBindingException 서명/클레임 검증 실패 시
    */
   private Jwt decodeIdToken(String idTokenValue) {
      try {
         return jwtDecoder.decode(idTokenValue);
      } catch (JwtException e) {
         log.warn("[Provider] ID Token 서명/클레임 검증 실패: {}", e.getMessage());
         throw new TokenBindingException(
             "ID Token 서명 또는 클레임(iss/exp/nbf) 검증에 실패했습니다: " + e.getMessage(), e);
      }
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
    * <p><b>알려진 제약(Opaque Access Token):</b> Access Token이 Opaque(비-JWT) 형식이면
    * Keycloak Introspect 응답이 {@code active} 여부만 노출하므로(라이브러리 제약) 로컬 aud/azp/subject
    * 결합 검증을 수행할 수 없습니다. 이 경우 UserInfo 200 응답 + subject 일치 검증으로만 보호됩니다
    * (기존 정책과 동일, 회귀 없음).</p>
    *
    * @param accessTokenValue Access Token
    * @param idTokenSubject   서명 검증이 완료된 ID Token에서 추출한 subject
    * @throws TokenBindingException Access Token이 JWT 구조인데 서명/클레임 검증에 실패했거나,
    *     azp/subject 결합 검증에 실패한 경우
    */
   private void validateAccessTokenIfJwt(String accessTokenValue, String idTokenSubject) {
      if (!JwtUtil.isStructurallyJwt(accessTokenValue)) {
         log.debug("[Provider] Access Token이 JWT 구조가 아님(Opaque 추정) — aud/azp/subject 로컬 결합 검증 스킵.");
         return;
      }
      try {
         Jwt accessToken = jwtDecoder.decode(accessTokenValue);
         TokenBindingValidator.validateAccessTokenAzp(accessToken, clientId);
         TokenBindingValidator.validateAccessTokenSubject(accessToken, idTokenSubject);
      } catch (JwtException e) {
         log.warn("[Provider] Access Token 서명/클레임 검증 실패: {}", e.getMessage());
         throw new TokenBindingException(
             "Access Token 서명 또는 클레임 검증에 실패했습니다: " + e.getMessage(), e);
      }
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
    * 서명 검증이 완료된 ID Token {@link Jwt}에서 OidcIdToken 객체를 생성합니다.
    *
    * @param idTokenValue ID Token 문자열
    * @param idToken      서명 검증이 완료된 {@link Jwt}
    * @return OidcIdToken 객체
    */
   private OidcIdToken createOidcIdToken(String idTokenValue, Jwt idToken) {
      return new OidcIdToken(idTokenValue, idToken.getIssuedAt(), idToken.getExpiresAt(), idToken.getClaims());
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
      Collection<GrantedAuthority> authorities =
          KeycloakAuthorityExtractor.extract(claims, clientId, roleMapping);

      log.debug("[Provider] 사용자 '{}' Principal 생성 완료. 권한: {}", subject, authorities);

      return new KeycloakPrincipal(subject, authorities, oidcIdToken, oidcUserInfo);
   }

   @Override
   public boolean supports(Class<?> authentication) {
      return KeycloakAuthentication.class.isAssignableFrom(authentication);
   }
}