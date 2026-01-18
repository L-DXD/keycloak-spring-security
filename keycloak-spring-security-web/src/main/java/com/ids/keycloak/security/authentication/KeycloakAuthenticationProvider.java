package com.ids.keycloak.security.authentication;

import static com.ids.keycloak.security.config.KeycloakSecurityConstants.REGISTRATION_ID;
import static com.ids.keycloak.security.config.KeycloakSecurityConstants.ROLE_PREFIX;

import com.ids.keycloak.security.exception.AuthenticationFailedException;
import com.ids.keycloak.security.exception.ConfigurationException;
import com.ids.keycloak.security.exception.RefreshTokenException;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.util.JwtUtil;
import com.sd.KeycloakClient.dto.auth.KeycloakTokenInfo;
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
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.client.RestClientException;

/**
 * {@link KeycloakAuthentication}을 처리하는 {@link AuthenticationProvider} 구현체입니다. ID Token의 유효성을 검증하고, 만료 시 재발급을 시도하며, 인증된
 * {@link KeycloakPrincipal}을 생성합니다. 토큰 저장/조회 책임은 이 클래스에서 제거되었습니다.
 */
@Slf4j
public class KeycloakAuthenticationProvider implements AuthenticationProvider {

   private final JwtDecoder jwtDecoder;
   private final KeycloakClient keycloakClient;
   private final ClientRegistrationRepository clientRegistrationRepository; // clientId 조회를 위해 의존성 다시 추가

   public KeycloakAuthenticationProvider(
       JwtDecoder jwtDecoder,
       KeycloakClient keycloakClient,
       ClientRegistrationRepository clientRegistrationRepository // 의존성 다시 추가
   ) {
      this.jwtDecoder = jwtDecoder;
      this.keycloakClient = keycloakClient;
      this.clientRegistrationRepository = clientRegistrationRepository;
   }

   @Override
   public Authentication authenticate(Authentication authentication) throws AuthenticationException {
      log.debug("[Provider] 인증 요청 시작: {}", authentication.getName());
      KeycloakAuthentication authRequest = (KeycloakAuthentication) authentication;
      String idTokenValue = (String) authRequest.getCredentials();
      String accessTokenValue = authRequest.getAccessToken();

      // 토큰 만료 여부를 먼저 확인 (Nimbus JWT 라이브러리 사용)
      if (JwtUtil.isTokenExpired(idTokenValue) || JwtUtil.isTokenExpired(accessTokenValue)) {
         log.warn("[Provider] 토큰 만료 확인, 리프레시를 시도합니다.");
         return authenticateWithRefreshToken(authRequest);
      }

      // 토큰이 만료되지 않은 경우에만 검증 시도
      try {
         return authenticateWithIdToken(authRequest);
      } catch (JwtException e) {
         log.error("[Provider] 토큰 검증 실패 (만료 외 사유). 원인: {}", e.getMessage());
         throw new AuthenticationFailedException("토큰 검증 실패: " + e.getMessage());
      }
   }

   private Authentication authenticateWithIdToken(KeycloakAuthentication authRequest) {
      String idTokenValue = (String) authRequest.getCredentials();
      String accessTokenValue = authRequest.getAccessToken();

      log.debug("[Provider] ID 토큰 검증 시도.");
      Jwt idToken = jwtDecoder.decode(idTokenValue);
      Jwt accessToken = jwtDecoder.decode(accessTokenValue);

      // 온라인 검증 (필요 시)
      keycloakClient.auth().authenticationByIntrospect(idTokenValue);

      log.debug("[Provider] ID 토큰 검증 성공. 인증된 객체 생성 시작.");
      return createAuthenticatedToken(idToken, accessToken, null);
   }

   private Authentication authenticateWithRefreshToken(KeycloakAuthentication authRequest) {
      log.debug("[Provider] Refresh Token으로 인증 시도.");

      if (!(authRequest.getDetails() instanceof String refreshTokenValue)) {
         throw new RefreshTokenException("인증 요청에 Refresh Token 정보가 없습니다.");
      }

      KeycloakTokenInfo newTokens = refreshTokens(refreshTokenValue);
      log.debug("[Provider] 새 토큰 발급 성공.");
      Jwt newIdToken = jwtDecoder.decode(newTokens.getIdToken());
      Jwt newAccessToken = jwtDecoder.decode(newTokens.getAccessToken());
      log.debug("[Provider] 새 ID/Access 토큰 검증 성공. 인증된 객체 생성 시작.");

      return createAuthenticatedToken(newIdToken, newAccessToken, newTokens);
   }

   private Authentication createAuthenticatedToken(Jwt validatedIdToken, Jwt validatedAccessToken, KeycloakTokenInfo newTokens) {
      ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID);
      if (clientRegistration == null) {
         throw new ConfigurationException("clientRegistration에 id를 찾을 수 없습니다. ");
      }
      String clientId = clientRegistration.getClientId();

      KeycloakPrincipal principal = createPrincipal(validatedAccessToken, clientId);
      KeycloakAuthentication authenticatedToken = new KeycloakAuthentication(principal, validatedIdToken.getTokenValue(), validatedAccessToken.getTokenValue());

      if (newTokens != null) {
         authenticatedToken.setDetails(newTokens);
      }

      log.debug("[Provider] 최종 인증 객체 생성 완료: {}", principal.getName());
      return authenticatedToken;
   }

   private KeycloakTokenInfo refreshTokens(String refreshTokenValue) {
      log.debug("[Provider] Keycloak에 토큰 재발급 요청...");
      try {
         return keycloakClient.auth().reissueToken(refreshTokenValue).getBody()
             .orElseThrow(() -> new RefreshTokenException("리프레쉬 토큰 발급 실패 (응답 없음)"));
      } catch (RestClientException e) {
         throw new AuthenticationFailedException();
      }
   }

   /**
    * 검증된 AccessToken의 'resource_access' 클레임에서 역할을 추출하여 Principal 객체를 생성합니다.
    *
    * @param accessToken 검증된 Access Token
    * @param clientId    역할을 추출할 대상 클라이언트 ID
    * @return 권한 정보가 포함된 Principal 객체
    */
   private KeycloakPrincipal createPrincipal(Jwt accessToken, String clientId) {
      Map<String, Object> claims = accessToken.getClaims();
      String subject = accessToken.getSubject();

      // 'resource_access' 클레임에서 clientId에 해당하는 역할(role) 목록을 추출합니다.
      List<String> roles = JwtUtil.extractRoles(claims, clientId);

      Collection<GrantedAuthority> authorities = new ArrayList<>();
      for (String role : roles) {
         // "ROLE_" 접두사는 Spring Security의 기본 규칙을 따릅니다.
         authorities.add(new SimpleGrantedAuthority(ROLE_PREFIX + role));
      }

      log.debug("[Provider] 사용자 '{}'의 권한 매핑 완료: {}", subject, authorities);
      return new KeycloakPrincipal(subject, authorities, claims);
   }

   @Override
   public boolean supports(Class<?> authentication) {
      return KeycloakAuthentication.class.isAssignableFrom(authentication);
   }
}