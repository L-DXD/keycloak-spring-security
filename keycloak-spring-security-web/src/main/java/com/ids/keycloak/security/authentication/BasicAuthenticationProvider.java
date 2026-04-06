package com.ids.keycloak.security.authentication;

import com.ids.keycloak.security.exception.AuthenticationFailedException;
import com.ids.keycloak.security.exception.ConfigurationException;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

/**
 * Basic Auth credentials로 Keycloak Direct Access Grants (Resource Owner Password Credentials) 인증을 수행하는
 * {@link AuthenticationProvider} 구현체입니다.
 * <p>
 * username/password를 Keycloak token endpoint에 전달하여 토큰을 교환하고,
 * 기존 {@link KeycloakAuthenticationProvider}의 {@code createAuthenticatedToken()} 메서드를 재사용하여
 * {@link KeycloakPrincipal} 기반의 인증 객체를 생성합니다.
 * </p>
 */
@Slf4j
public class BasicAuthenticationProvider implements AuthenticationProvider {

    private final String tokenEndpoint;
    private final String clientId;
    private final String clientSecret;
    private final KeycloakAuthenticationProvider oidcProvider;
    private final RestTemplate restTemplate;

    /**
     * BasicAuthenticationProvider를 생성합니다.
     *
     * @param tokenEndpoint Keycloak token endpoint URL
     * @param clientId      OAuth2 클라이언트 ID
     * @param clientSecret  OAuth2 클라이언트 시크릿
     * @param oidcProvider  기존 OIDC 인증 Provider (createAuthenticatedToken 재사용)
     */
    public BasicAuthenticationProvider(
        String tokenEndpoint,
        String clientId,
        String clientSecret,
        KeycloakAuthenticationProvider oidcProvider
    ) {
        this.tokenEndpoint = tokenEndpoint;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.oidcProvider = oidcProvider;
        this.restTemplate = new RestTemplate();
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        BasicAuthenticationToken token = (BasicAuthenticationToken) authentication;
        String username = token.getUsername();
        String password = token.getPassword();

        log.debug("[BasicAuthProvider] Direct Access Grants 인증 시도: username={}", username);

        try {
            // Keycloak token endpoint 호출 (Resource Owner Password Credentials Grant)
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "password");
            body.add("client_id", clientId);
            body.add("client_secret", clientSecret);
            body.add("username", username);
            body.add("password", password);
            body.add("scope", "openid");

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

            @SuppressWarnings("unchecked")
            ResponseEntity<Map> response = restTemplate.postForEntity(tokenEndpoint, request, Map.class);

            if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
                log.warn("[BasicAuthProvider] Direct Access Grants 인증 실패: status={}", response.getStatusCode());
                throw new AuthenticationFailedException("Basic Auth 인증 실패: 잘못된 자격 증명입니다.");
            }

            @SuppressWarnings("unchecked")
            Map<String, Object> tokenResponse = response.getBody();
            String idTokenValue = (String) tokenResponse.get("id_token");
            String accessTokenValue = (String) tokenResponse.get("access_token");

            if (idTokenValue == null || accessTokenValue == null) {
                log.warn("[BasicAuthProvider] 토큰 응답에 id_token 또는 access_token이 없습니다.");
                throw new AuthenticationFailedException("Basic Auth 인증 실패: 토큰 응답이 불완전합니다.");
            }

            log.debug("[BasicAuthProvider] Direct Access Grants 토큰 교환 성공. Principal 생성 시작.");

            // 기존 KeycloakAuthenticationProvider의 createAuthenticatedToken() 재사용
            Authentication oidcAuth = oidcProvider.createAuthenticatedToken(idTokenValue, accessTokenValue);
            KeycloakPrincipal principal = (KeycloakPrincipal) oidcAuth.getPrincipal();

            // BasicAuthenticationToken으로 래핑하여 반환
            BasicAuthenticationToken authenticatedToken = new BasicAuthenticationToken(
                principal, idTokenValue, accessTokenValue
            );

            log.debug("[BasicAuthProvider] Basic Auth 인증 완료: {}", principal.getName());
            return authenticatedToken;

        } catch (RestClientException e) {
            log.warn("[BasicAuthProvider] Keycloak 서버 통신 실패: {}", e.getMessage());
            throw new AuthenticationFailedException("Basic Auth 인증 실패: " + e.getMessage());
        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            log.error("[BasicAuthProvider] 예상치 못한 오류: {}", e.getMessage(), e);
            throw new ConfigurationException("Basic Auth 인증 중 오류가 발생했습니다: " + e.getMessage());
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return BasicAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
