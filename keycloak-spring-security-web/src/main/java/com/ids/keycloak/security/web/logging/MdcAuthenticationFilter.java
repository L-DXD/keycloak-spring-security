package com.ids.keycloak.security.web.logging;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.filter.OncePerRequestFilter;

import com.ids.keycloak.security.authentication.KeycloakPrincipal;
import com.ids.keycloak.security.config.KeycloakLoggingSettings;
import com.ids.keycloak.security.logging.LoggingContextAccessor;
import com.ids.keycloak.security.logging.LoggingContextKeys;
import com.ids.keycloak.security.logging.LoggingValueSanitizer;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 인증이 끝난 뒤({@code AuthorizationFilter} 앞) 사용자 정보를 MDC에 넣는다. 키는 v2와 같다.
 * <ul>
 *   <li>{@code userId}: Keycloak {@code sub}</li>
 *   <li>{@code username}: {@code preferred_username}. 이메일일 수 있어 {@link LoggingValueSanitizer}를 거친다(v3에서 바뀜)</li>
 *   <li>{@code sessionId}: Keycloak 세션 id(토큰의 {@code sid}). 라이브러리 sid 쿠키 값이 아니다</li>
 * </ul>
 * 지우기는 {@link MdcRequestFilter}가 한다.
 */
public class MdcAuthenticationFilter extends OncePerRequestFilter {

    private final LoggingContextAccessor context;
    private final KeycloakLoggingSettings settings;
    private final LoggingValueSanitizer sanitizer;
    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();

    public MdcAuthenticationFilter(LoggingContextAccessor context, KeycloakLoggingSettings settings, LoggingValueSanitizer sanitizer) {
        this.context = Objects.requireNonNull(context);
        this.settings = Objects.requireNonNull(settings);
        this.sanitizer = Objects.requireNonNull(sanitizer);
    }

    public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy strategy) {
        this.securityContextHolderStrategy = Objects.requireNonNull(strategy);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
        throws ServletException, IOException {
        Authentication authentication = securityContextHolderStrategy.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated() && !(authentication instanceof AnonymousAuthenticationToken)) {
            putUser(authentication);
        }
        chain.doFilter(request, response);
    }

    /** 사용자 정보를 MDC에 넣는다. 다른 주체 타입을 쓰면 덮어쓴다. */
    protected void putUser(Authentication authentication) {
        Object principal = authentication.getPrincipal();
        if (principal instanceof KeycloakPrincipal keycloak) {
            put(keycloak.subject(), keycloak.username(), keycloak.sessionId());
        } else if (principal instanceof OidcUser oidc) {
            put(oidc.getSubject(), oidc.getPreferredUsername(), claim(oidc.getClaims(), "sid"));
        } else if (principal instanceof Jwt jwt) {
            put(jwt.getSubject(), jwt.getClaimAsString("preferred_username"), jwt.getClaimAsString("sid"));
        } else {
            put(null, authentication.getName(), null);
        }
    }

    private void put(String userId, String username, String sessionId) {
        if (settings.includeUserId()) {
            context.put(LoggingContextKeys.USER_ID, userId);
        }
        if (settings.includeUsername() && username != null) {
            context.put(LoggingContextKeys.USERNAME, sanitizer.sanitize(LoggingContextKeys.USERNAME, username));
        }
        if (settings.includeSessionId()) {
            context.put(LoggingContextKeys.SESSION_ID, sessionId);
        }
    }

    private static String claim(Map<String, Object> claims, String name) {
        Object value = claims == null ? null : claims.get(name);
        return value == null ? null : value.toString();
    }
}
