package com.ids.keycloak.security.authentication;

import static com.ids.keycloak.security.config.KeycloakSecurityConstants.REGISTRATION_ID;
import static com.ids.keycloak.security.config.KeycloakSecurityConstants.ROLE_PREFIX;

import com.ids.keycloak.security.exception.AuthenticationFailedException;
import com.ids.keycloak.security.exception.ConfigurationException;
import com.ids.keycloak.security.exception.IntrospectionFailedException;
import com.ids.keycloak.security.exception.RefreshTokenException;
import com.ids.keycloak.security.exception.TokenExpiredException;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.util.JwtUtil;
import com.sd.KeycloakClient.dto.KeycloakResponse;
import com.sd.KeycloakClient.dto.auth.KeycloakIntrospectResponse;
import com.sd.KeycloakClient.dto.auth.KeycloakTokenInfo;
import com.sd.KeycloakClient.factory.KeycloakClient;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
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

      try {
         return authenticateWithIdToken(authRequest);
      } catch (TokenExpiredException | IntrospectionFailedException e) {
         log.warn("[Provider] 토큰 만료 또는 온라인 검증 실패, 리프레시를 시도합니다. 원인: {}", e.getMessage());
         return authenticateWithRefreshToken(authRequest);
      } catch (JwtException e) {
         log.error("[Provider] 토큰 검증 실패 (만료 외 사유). 원인: {}", e.getMessage());
         throw new AuthenticationFailedException("토큰 검증 실패: " + e.getMessage());
      }
   }

   private Authentication authenticateWithIdToken(KeycloakAuthentication authRequest) {
      String idTokenValue = authRequest.getIdToken();
      String accessTokenValue = authRequest.getAccessToken();

      log.debug("[Provider] ID 토큰 검증 시도.");

      // 오프라인 검증 (만료 체크 + 서명, 클레임 등)
      Jwt idToken = decodeToken(idTokenValue);
      Jwt accessToken = decodeToken(accessTokenValue);

      // 온라인 검증 (Keycloak Introspect)
      verifyTokenOnline(accessTokenValue);

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
      Jwt newIdToken = decodeToken(newTokens.getIdToken());
      Jwt newAccessToken = decodeToken(newTokens.getAccessToken());
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

   /**
    * Refresh Token을 사용하여 새로운 토큰을 발급받습니다.
    *
    * @param refreshTokenValue Refresh Token
    * @return 새로 발급된 토큰 정보
    * @throws RefreshTokenException Refresh Token이 만료되었거나 유효하지 않은 경우 (401)
    * @throws ConfigurationException Keycloak 서버 오류 또는 통신 오류 (500)
    * @throws AuthenticationFailedException 그 외 예상치 못한 응답
    */
   private KeycloakTokenInfo refreshTokens(String refreshTokenValue) {
      log.debug("[Provider] Keycloak에 토큰 재발급 요청...");
      try {
         KeycloakResponse<KeycloakTokenInfo> response = keycloakClient.auth().reissueToken(refreshTokenValue);
         int status = response.getStatus();

         return switch (status) {
            case 200 -> {
               log.debug("[Provider] 토큰 재발급 성공.");
               yield response.getBody()
                   .orElseThrow(() -> new RefreshTokenException("토큰 재발급 실패: 응답 본문이 없습니다."));
            }
            case 401 -> {
               log.warn("[Provider] Refresh Token이 만료되었거나 유효하지 않습니다.");
               throw new RefreshTokenException("Refresh Token이 만료되었거나 유효하지 않습니다.");
            }
            case 500 -> {
               log.error("[Provider] Keycloak 서버 오류 발생.");
               throw new ConfigurationException("Keycloak 서버에 오류가 발생했습니다.");
            }
            default -> {
               log.error("[Provider] 토큰 재발급 중 예상치 못한 응답. 상태 코드: {}", status);
               throw new AuthenticationFailedException("토큰 재발급 실패. 상태 코드: " + status);
            }
         };
      } catch (RestClientException e) {
         log.error("[Provider] Keycloak 서버와 통신 중 오류 발생: {}", e.getMessage());
         throw new ConfigurationException("Keycloak 서버와 통신할 수 없습니다: " + e.getMessage());
      }
   }

   /**
    * JWT 토큰을 디코딩하고 만료 여부를 확인합니다.
    * 만료된 토큰인 경우 {@link TokenExpiredException}을 던집니다.
    *
    * @param token JWT 토큰 문자열
    * @return 디코딩된 Jwt 객체
    * @throws TokenExpiredException 토큰이 만료된 경우
    */
   private Jwt decodeToken(String token) {
      if (JwtUtil.isTokenExpired(token)) {
         throw new TokenExpiredException("토큰이 만료되었습니다.");
      }
      return jwtDecoder.decode(token);
   }

   /**
    * Keycloak Introspect API를 통해 토큰을 온라인으로 검증합니다.
    *
    * @param accessToken 검증할 Access Token
    * @throws IntrospectionFailedException 토큰이 유효하지 않은 경우 (401)
    * @throws ConfigurationException Keycloak 서버 오류 (500)
    * @throws AuthenticationFailedException 그 외 예상치 못한 응답
    */
   private void verifyTokenOnline(String accessToken) {
      try {
         KeycloakResponse<KeycloakIntrospectResponse> response = keycloakClient.auth().authenticationByIntrospect(accessToken);
         int status = response.getStatus();

         switch (status) {
            case 200 -> log.debug("[Provider] 온라인 검증 성공.");
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