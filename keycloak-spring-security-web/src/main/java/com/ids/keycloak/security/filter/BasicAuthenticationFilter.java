package com.ids.keycloak.security.filter;

import com.ids.keycloak.security.authentication.BasicAuthenticationToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * {@code Authorization: Basic} 헤더를 파싱하여 Keycloak Direct Access Grants 인증을 시도하는 필터입니다.
 * <p>
 * Basic 헤더가 없으면 다음 필터로 넘기고 (기존 OIDC 쿠키 인증 흐름),
 * Basic 헤더가 있으면 credentials를 디코딩하여 {@link BasicAuthenticationToken}을 생성하고
 * {@link AuthenticationManager}에 인증을 위임합니다.
 * </p>
 * <p>
 * Basic Auth는 stateless로 동작합니다. 매 요청마다 인증하며 세션을 생성하지 않습니다.
 * </p>
 */
@Slf4j
public class BasicAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BASIC_PREFIX = "Basic ";

    private final AuthenticationManager authenticationManager;

    public BasicAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {

        String authHeader = request.getHeader(AUTHORIZATION_HEADER);

        // Basic 헤더가 없으면 다음 필터로 넘김 (OIDC 쿠키 흐름)
        if (authHeader == null || !authHeader.startsWith(BASIC_PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        log.debug("[BasicAuthFilter] Authorization: Basic 헤더 감지. 인증 시도.");

        try {
            // Base64 디코딩 → username:password 분리
            String base64Credentials = authHeader.substring(BASIC_PREFIX.length()).trim();
            String credentials = new String(Base64.getDecoder().decode(base64Credentials), StandardCharsets.UTF_8);
            int colonIndex = credentials.indexOf(':');

            if (colonIndex < 0) {
                log.warn("[BasicAuthFilter] 잘못된 Basic 인증 형식 (콜론 없음).");
                SecurityContextHolder.clearContext();
                filterChain.doFilter(request, response);
                return;
            }

            String username = credentials.substring(0, colonIndex);
            String password = credentials.substring(colonIndex + 1);

            // BasicAuthenticationToken 생성 및 인증 시도
            BasicAuthenticationToken authRequest = new BasicAuthenticationToken(username, password);
            Authentication result = authenticationManager.authenticate(authRequest);

            // 인증 성공 → SecurityContext에 설정
            SecurityContextHolder.getContext().setAuthentication(result);
            log.debug("[BasicAuthFilter] Basic Auth 인증 성공: {}", result.getName());

        } catch (AuthenticationException e) {
            SecurityContextHolder.clearContext();
            log.warn("[BasicAuthFilter] Basic Auth 인증 실패: {}", e.getMessage());
            // 인증 실패 시에도 filterChain을 진행하여 EntryPoint가 401 처리
        } catch (IllegalArgumentException e) {
            SecurityContextHolder.clearContext();
            log.warn("[BasicAuthFilter] Base64 디코딩 실패: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }
}
