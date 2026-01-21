package com.ids.keycloak.security.authentication;

import static com.ids.keycloak.security.config.KeycloakSecurityConstants.REGISTRATION_ID;
import static com.ids.keycloak.security.config.KeycloakSecurityConstants.ROLE_PREFIX;

import com.ids.keycloak.security.exception.AuthenticationFailedException;
import com.ids.keycloak.security.exception.ConfigurationException;
import com.ids.keycloak.security.exception.IntrospectionFailedException;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.util.JwtUtil;
import com.sd.KeycloakClient.dto.KeycloakResponse;
import com.sd.KeycloakClient.dto.auth.KeycloakIntrospectResponse;
import com.sd.KeycloakClient.factory.KeycloakClient;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
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
   private final ClientRegistrationRepository clientRegistrationRepository;

   public KeycloakAuthenticationProvider(
       KeycloakClient keycloakClient,
       ClientRegistrationRepository clientRegistrationRepository
   ) {
      this.keycloakClient = keycloakClient;
      this.clientRegistrationRepository = clientRegistrationRepository;
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
      ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID);
      if (clientRegistration == null) {
         throw new ConfigurationException("clientRegistration에 id를 찾을 수 없습니다. ");
      }
      String clientId = clientRegistration.getClientId();

      // ID Token에서 subject(사용자 ID)와 클레임 추출
      Map<String, Object> idTokenClaims = JwtUtil.parseClaimsWithoutValidation(idTokenValue);
      String subject = JwtUtil.parseSubjectWithoutValidation(idTokenValue);

      // Access Token에서 역할(roles) 정보 추출을 위한 클레임 파싱
      Map<String, Object> accessTokenClaims = JwtUtil.parseClaimsWithoutValidation(accessTokenValue);

      KeycloakPrincipal principal = createPrincipal(idTokenClaims, accessTokenClaims, subject, clientId);
      KeycloakAuthentication authenticatedToken = new KeycloakAuthentication(principal, idTokenValue, accessTokenValue, true);

      log.debug("[Provider] 최종 인증 객체 생성 완료: {}", principal.getName());
      return authenticatedToken;
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
    * ID Token과 Access Token 클레임에서 Principal 객체를 생성합니다.
    *
    * @param idTokenClaims     ID Token 클레임 (사용자 정보)
    * @param accessTokenClaims Access Token 클레임 (역할 정보)
    * @param subject           사용자 ID (ID Token에서 추출)
    * @param clientId          역할을 추출할 대상 클라이언트 ID
    * @return 권한 정보가 포함된 Principal 객체
    */
   private KeycloakPrincipal createPrincipal(Map<String, Object> idTokenClaims, Map<String, Object> accessTokenClaims, String subject, String clientId) {
      // Access Token의 'resource_access' 클레임에서 clientId에 해당하는 역할(role) 목록을 추출합니다.
      List<String> roles = JwtUtil.extractRoles(accessTokenClaims, clientId);

      Collection<GrantedAuthority> authorities = new ArrayList<>();
      for (String role : roles) {
         // "ROLE_" 접두사는 Spring Security의 기본 규칙을 따릅니다.
         authorities.add(new SimpleGrantedAuthority(ROLE_PREFIX + role));
      }

      log.debug("[Provider] 사용자 '{}'의 권한 매핑 완료: {}", subject, authorities);
      // Principal에는 ID Token 클레임을 저장 (사용자 정보)
      return new KeycloakPrincipal(subject, authorities, idTokenClaims);
   }

   @Override
   public boolean supports(Class<?> authentication) {
      return KeycloakAuthentication.class.isAssignableFrom(authentication);
   }
}