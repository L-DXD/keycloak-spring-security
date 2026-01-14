package com.ids.keycloak.security.filter;

import com.ids.keycloak.security.config.KeycloakSecurityConstants;
import com.ids.keycloak.security.config.KeycloakSecurityProperties;
import com.ids.keycloak.security.config.KeycloakLoggingProperties;
import com.ids.keycloak.security.logging.LoggingContextAccessor;
import com.ids.keycloak.security.logging.LoggingContextKeys;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

/**
 * 인증 완료 후 사용자 정보를 MDC에 추가하는 필터.
 * <p>
 * SecurityFilterChain에서 인증 필터 이후에 위치해야 합니다.
 * <ul>
 *   <li>{@code userId}: Keycloak sub claim (사용자 고유 ID)</li>
 *   <li>{@code username}: preferred_username claim</li>
 *   <li>{@code sessionId}: Keycloak sid claim (세션 ID)</li>
 * </ul>
 * <p>
 * MDC 정리는 {@link MdcRequestFilter}에서 담당합니다.
 *
 * @author LeeBongSeung
 * @see MdcRequestFilter
 */
public class MdcAuthenticationFilter extends OncePerRequestFilter {

    private final LoggingContextAccessor contextAccessor;
    private final KeycloakSecurityProperties securityProperties;

    public MdcAuthenticationFilter(LoggingContextAccessor contextAccessor, KeycloakSecurityProperties securityProperties) {
        this.contextAccessor = contextAccessor;
        this.securityProperties = securityProperties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        populateAuthenticationContext();
        chain.doFilter(request, response);
        // MDC clear는 MdcRequestFilter에서 담당
    }

    private void populateAuthenticationContext() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || !auth.isAuthenticated()) {
            return;
        }

        if (auth instanceof AnonymousAuthenticationToken) {
            return;
        }

        Object principal = auth.getPrincipal();
        KeycloakLoggingProperties loggingProps = securityProperties.getLogging();

        if (principal instanceof KeycloakPrincipal keycloakPrincipal) {
            populateFromAttributes(keycloakPrincipal.getAttributes(), loggingProps);
        } else if (principal instanceof OidcUser oidcUser) {
            populateFromAttributes(oidcUser.getAttributes(), loggingProps);
        } else if (principal instanceof Jwt jwt) {
            populateFromAttributes(jwt.getClaims(), loggingProps);
        } else {
            // 알 수 없는 Principal 타입의 경우 설정 확인 후 이름 저장
            if (loggingProps.isIncludeUsername()) {
                contextAccessor.put(LoggingContextKeys.USERNAME, auth.getName());
            }
        }
    }

    private void populateFromAttributes(Map<String, Object> attributes, KeycloakLoggingProperties loggingProps) {
        if (attributes == null || attributes.isEmpty()) {
            return;
        }

        // userId (sub)
        if (loggingProps.isIncludeUserId()) {
            Object sub = attributes.get(KeycloakSecurityConstants.SUB_CLAIM);
            if (sub != null) {
                contextAccessor.put(LoggingContextKeys.USER_ID, sub.toString());
            }
        }

        // username (preferred_username)
        if (loggingProps.isIncludeUsername()) {
            Object username = attributes.get(KeycloakSecurityConstants.PREFERRED_USERNAME_CLAIM);
            if (username != null) {
                contextAccessor.put(LoggingContextKeys.USERNAME, username.toString());
            }
        }

        // sessionId (sid)
        if (loggingProps.isIncludeSessionId()) {
            Object sid = attributes.get(KeycloakSecurityConstants.SID_CLAIM);
            if (sid != null) {
                contextAccessor.put(LoggingContextKeys.SESSION_ID, sid.toString());
            }
        }
    }
}
