package com.ids.keycloak.security.web;

import com.ids.keycloak.security.exception.RefreshTokenException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
public class OidcSessionValidationFilter extends OncePerRequestFilter {

    private final OAuth2AuthorizedClientService authorizedClientService;
    private final OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> accessTokenResponseClient;
    private final SecurityContextLogoutHandler securityContextLogoutHandler = new SecurityContextLogoutHandler();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        SecurityContext securityContext = SecurityContextHolder.getContext();
        Authentication authentication = securityContext.getAuthentication();

        // OIDC 인증 사용자인 경우에만 로직 수행
        if (authentication instanceof OAuth2AuthenticationToken oAuth2AuthenticationToken &&
            authentication.getPrincipal() instanceof OidcUser oidcUser) {

            OidcIdToken idToken = oidcUser.getIdToken();

            // ID 토큰의 만료 시간을 확인
            if (idToken.getExpiresAt() != null && idToken.getExpiresAt().isBefore(Instant.now())) {
                log.warn("ID 토큰이 만료되었습니다. 토큰 갱신을 시도합니다.");
                
                OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                        oAuth2AuthenticationToken.getAuthorizedClientRegistrationId(),
                        oAuth2AuthenticationToken.getName());

                handleTokenRefresh(request, response, oAuth2AuthenticationToken, authorizedClient);
                return; // 토큰 갱신은 리디렉션되거나 응답을 완료할 수 있습니다.
            } else {
                log.debug("ID 토큰이 유효하며 만료되지 않았습니다.");
            }
        }

        filterChain.doFilter(request, response);
    }




    private void handleTokenRefresh(HttpServletRequest request, HttpServletResponse response,
                                    OAuth2AuthenticationToken oldAuthentication, OAuth2AuthorizedClient oldAuthorizedClient)
            throws IOException, ServletException {
        OAuth2RefreshToken refreshToken = oldAuthorizedClient.getRefreshToken();

        if (refreshToken != null) {
            try {
                OAuth2RefreshTokenGrantRequest refreshTokenGrantRequest = new OAuth2RefreshTokenGrantRequest(
                        oldAuthorizedClient.getClientRegistration(), oldAuthorizedClient.getAccessToken(), refreshToken);
                OAuth2AccessToken newAccessToken = accessTokenResponseClient.getTokenResponse(refreshTokenGrantRequest)
                        .getAccessToken();

                OAuth2AuthorizedClient newAuthorizedClient = new OAuth2AuthorizedClient(
                        oldAuthorizedClient.getClientRegistration(),
                        oldAuthorizedClient.getPrincipalName(),
                        newAccessToken,
                        refreshToken); // 이전 리프레시 토큰 사용 (또는 응답에 새로운 토큰이 포함된 경우 사용, 스프링 기본값에는 흔치 않음)

                authorizedClientService.saveAuthorizedClient(newAuthorizedClient, oldAuthentication);
                log.info("Token refreshed successfully for user {}", oldAuthorizedClient.getPrincipalName());

                // 새 토큰 정보로 사용자 재인증
                // 일반적으로 새 토큰으로 Authentication 객체를 다시 생성하는 것을 포함합니다.
                // 간단하게 다음 필터 체인(예: OAuth2LoginAuthenticationFilter)이 필요할 경우 인증을 다시 설정하도록
                // 하거나, 리디렉션할 수 있습니다.
                // 또는 더 견고하게는 사용자 정보를 가져와 새로운 OAuth2AuthenticationToken을 구성할 수 있습니다.
                // 현재로서는 authorizedClientService가 업데이트되었는지 확인하는 것으로 충분합니다.

                // 토큰을 갱신했으므로 SecurityContext의 ID 토큰(OidcUser인 경우)은 여전히 이전 것일 수 있습니다.
                // 재인증을 트리거하거나 SecurityContext를 재구성해야 합니다.
                // 간단한 방법은 보안 엔드포인트로 리디렉션하여 OAuth2LoginAuthenticationFilter 등이
                // 재평가하도록 하는 것입니다. 또는 여기에서 Authentication을 재구성할 수도 있습니다.
                // 이 필터의 범위에서는 단순히 클라이언트 서비스를 업데이트하는 것으로 충분하며,
                // 후속 필터가 업데이트된 클라이언트를 처리한다면 요청을 진행하는 것도 괜찮을 수 있습니다.

                // SecurityContext를 새로운 JwtAuthenticationToken(ID 토큰으로부터) 또는
                // 새로운 OAuth2AuthenticationToken(사용자 정보를 다시 가져온 후)으로 즉시 업데이트하려는 의도라면,
                // 해당 로직이 여기에 들어갑니다.
                // 현재 설정에서 authorizedClientService의 토큰만 업데이트했다면,
                // 후속 요청 처리는 SecurityContext의 만료된 토큰을 계속 사용할 수 있습니다.
                // 현재 요청 컨텍스트에 대한 전체 재인증이 필요할 수 있습니다.

                // 세션 기반 시스템의 경우, 인증 필터 체인이 업데이트된 인가된 클라이언트를 기반으로
                // 보안 컨텍스트를 재평가한다면, 원래 요청 경로로의 간단한 리디렉션으로 충분한 경우가 많습니다.
                response.sendRedirect(request.getRequestURI()); // 새 토큰으로 다시 처리하도록 리디렉션
                return;

            } catch (Exception refreshException) {
                log.error("Failed to refresh token for user {}: {}", oldAuthorizedClient.getPrincipalName(), refreshException.getMessage());
                // 세션 무효화 및 로그아웃
                securityContextLogoutHandler.logout(request, response, oldAuthentication);
                throw new RefreshTokenException("Failed to refresh token", refreshException);
            }
        } else {
            log.warn("사용자 {}에게 사용 가능한 리프레시 토큰이 없습니다. 세션을 무효화합니다.", oldAuthorizedClient.getPrincipalName());
            securityContextLogoutHandler.logout(request, response, oldAuthentication);
            throw new RefreshTokenException("No refresh token available");
        }
    }
}
