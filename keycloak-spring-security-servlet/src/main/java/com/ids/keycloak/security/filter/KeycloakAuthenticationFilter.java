package com.ids.keycloak.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.authentication.KeycloakAuthentication;
import com.ids.keycloak.security.model.PreAuthenticationPrincipal;
import com.ids.keycloak.security.util.CookieUtil;
import com.sd.KeycloakClient.dto.auth.KeycloakTokenInfo;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * HTTP 요청의 쿠키에서 Keycloak 토큰을 읽어 인증을 시도하는 필터입니다.
 * 토큰 저장/조회, 재발급 후처리 등 인증 흐름 전반을 총괄합니다.
 */
@Slf4j
public class KeycloakAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;
    private final OAuth2AuthorizedClientRepository authorizedClientRepository;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final ObjectMapper objectMapper;

    public KeycloakAuthenticationFilter(
        AuthenticationManager authenticationManager,
        OAuth2AuthorizedClientRepository authorizedClientRepository,
        ClientRegistrationRepository clientRegistrationRepository,
        ObjectMapper objectMapper
    ) {
        this.authenticationManager = authenticationManager;
        this.authorizedClientRepository = authorizedClientRepository;
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {

        String idTokenValue = CookieUtil.getCookieValue(request, CookieUtil.ID_TOKEN_NAME).orElse(null);
        String accessTokenValue = CookieUtil.getCookieValue(request, CookieUtil.ACCESS_TOKEN_NAME).orElse(null);

        if (idTokenValue == null) {
            log.trace("요청에 ID 토큰 쿠키가 없습니다. 다음 필터로 계속 진행합니다.");
            filterChain.doFilter(request, response);
            return;
        }

        try {
            PreAuthenticationPrincipal principal = createPrincipalFromIdToken(idTokenValue);
            KeycloakAuthentication authRequest = new KeycloakAuthentication(principal, idTokenValue, accessTokenValue);
            log.debug("[Filter] 인증 전 Authentication 객체 생성: {}", principal.getName());

            SecurityContext securityContext = SecurityContextHolder.getContext();
            Authentication existingAuthenticationInContext = securityContext.getAuthentication();

            OAuth2AuthorizedClient authorizedClient = null;
            if (existingAuthenticationInContext != null && existingAuthenticationInContext.isAuthenticated()) {
                // 두 번째 요청부터는 SecurityContext에 저장된 KeycloakAuthentication의 details에서 직접 가져옵니다.
                if (existingAuthenticationInContext.getDetails() instanceof OAuth2AuthorizedClient) {
                    authorizedClient = (OAuth2AuthorizedClient) existingAuthenticationInContext.getDetails();
                    log.debug("[Filter] SecurityContext의 기존 인증 정보에서 AuthorizedClient 로드 성공.");
                } else if (existingAuthenticationInContext instanceof OAuth2AuthenticationToken) {
                    // OIDC 로그인 직후의 첫 요청
                    log.debug("[Filter] SecurityContext에서 OAuth2AuthenticationToken 발견. 이를 사용하여 AuthorizedClient 로드.");
                    authorizedClient = authorizedClientRepository.loadAuthorizedClient(
                        ((OAuth2AuthenticationToken) existingAuthenticationInContext).getAuthorizedClientRegistrationId(),
                        existingAuthenticationInContext, request);
                }
            }
            log.debug("[Filter] 최종적으로 로드된 AuthorizedClient: {}", (authorizedClient != null ? "성공" : "실패 또는 없음"));

            authRequest.setDetails(authorizedClient);

            log.debug("[Filter] AuthenticationManager에 인증 위임...");
            Authentication successfulAuthentication = authenticationManager.authenticate(authRequest);
            log.debug("[Filter] 인증 성공: {}", successfulAuthentication.getName());

            OAuth2AuthorizedClient finalAuthorizedClient = authorizedClient;
            if (successfulAuthentication.getDetails() instanceof KeycloakTokenInfo newTokens) {
                log.debug("[Filter] 토큰 재발급 감지. 새로운 OAuth2AuthorizedClient 저장 및 쿠키 업데이트 시작.");
                finalAuthorizedClient = createNewAuthorizedClient(newTokens, successfulAuthentication);
                authorizedClientRepository.saveAuthorizedClient(finalAuthorizedClient, successfulAuthentication, request, response);
                updateCookies(response, newTokens);
            }

            // 최종 인증 객체의 details에, 조회했거나 새로 생성한 authorizedClient를 담아서 세션에 저장합니다.
            if (successfulAuthentication instanceof KeycloakAuthentication) {
                ((KeycloakAuthentication) successfulAuthentication).setDetails(finalAuthorizedClient);
            }

            securityContext.setAuthentication(successfulAuthentication);
            log.debug("[Filter] SecurityContext에 인증된 사용자 '{}'와 AuthorizedClient를 등록했습니다.", successfulAuthentication.getName());

        } catch (AuthenticationException e) {
            SecurityContextHolder.clearContext();
            log.warn("[Filter] Keycloak 인증에 실패했습니다: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            SecurityContextHolder.clearContext();
            log.error("[Filter] Keycloak 인증 과정에서 예상치 못한 오류가 발생했습니다.", e);
            throw new ServletException("Keycloak 인증 처리 중 오류 발생", e);
        }

        filterChain.doFilter(request, response);
    }
    
    private OAuth2AuthorizedClient createNewAuthorizedClient(KeycloakTokenInfo newTokens, Authentication authentication) {
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak");
        
        OAuth2AccessToken newAccessToken = new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            newTokens.getAccessToken(),
            Instant.now(),
            Instant.ofEpochSecond(newTokens.getExpireTime())
        );
        
        OAuth2RefreshToken newRefreshToken = (newTokens.getRefreshToken() != null)
            ? new OAuth2RefreshToken(newTokens.getRefreshToken(), Instant.now())
            : null;

        return new OAuth2AuthorizedClient(
            clientRegistration,
            authentication.getName(),
            newAccessToken,
            newRefreshToken
        );
    }
    
    private void updateCookies(HttpServletResponse response, KeycloakTokenInfo newTokens) {
        log.debug("[Filter] 토큰이 재발급되어 쿠키를 업데이트합니다.");
        int maxAge = CookieUtil.calculateRestMaxAge(newTokens.getExpireTime());
        CookieUtil.addTokenCookies(response, newTokens.getAccessToken(), maxAge, newTokens.getIdToken(), maxAge);
    }

    private PreAuthenticationPrincipal createPrincipalFromIdToken(String idToken) throws IOException {
        try {
            String[] parts = idToken.split("\\.");
            if (parts.length < 2) {
                return new PreAuthenticationPrincipal("unknown");
            }
            byte[] payloadBytes = Base64.getUrlDecoder().decode(parts[1]);
            Map<String, Object> payload = objectMapper.readValue(payloadBytes, Map.class);
            String subject = (String) payload.get("sub");
            if (subject == null || subject.isBlank()) {
                throw new IllegalArgumentException("ID Token에 'sub' 클레임이 없습니다.");
            }
            return new PreAuthenticationPrincipal(subject);
        } catch (IllegalArgumentException e) {
            log.warn("ID Token 파싱 중 오류 발생: {}", e.getMessage());
            return new PreAuthenticationPrincipal("unknown");
        }
    }
}
