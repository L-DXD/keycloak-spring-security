package com.ids.keycloak.security.web.reactive;

import com.ids.keycloak.security.logging.LoggingContextKeys;
import com.ids.keycloak.security.logging.WebFluxContextAccessor;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

/**
 * 인증 완료 후 사용자 정보를 Reactor Context에 추가하는 WebFilter.
 * <p>
 * SecurityWebFilterChain에서 인증 필터 이후에 위치해야 합니다.
 * <ul>
 *   <li>{@code userId}: Keycloak sub claim (사용자 고유 ID)</li>
 *   <li>{@code username}: preferred_username claim</li>
 *   <li>{@code sessionId}: Keycloak sid claim (세션 ID)</li>
 * </ul>
 * <p>
 * MDC 정리는 {@link MdcRequestWebFilter}에서 담당합니다.
 *
 * @author LeeBongSeung
 * @since 1.0.0
 * @see MdcRequestWebFilter
 */
public class MdcAuthenticationWebFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(this::isAuthenticated)
                .flatMap(auth -> chain.filter(exchange)
                        .contextWrite(context -> populateAuthenticationContext(context, auth)))
                .switchIfEmpty(chain.filter(exchange));
    }

    private boolean isAuthenticated(Authentication auth) {
        if (auth == null || !auth.isAuthenticated()) {
            return false;
        }
        return !(auth instanceof AnonymousAuthenticationToken);
    }

    private Context populateAuthenticationContext(Context context, Authentication auth) {
        String userId = extractUserId(auth);
        if (userId != null) {
            context = WebFluxContextAccessor.put(context, LoggingContextKeys.USER_ID, userId);
        }

        String username = extractUsername(auth);
        if (username != null) {
            context = WebFluxContextAccessor.put(context, LoggingContextKeys.USERNAME, username);
        }

        String sessionId = extractSessionId(auth);
        if (sessionId != null) {
            context = WebFluxContextAccessor.put(context, LoggingContextKeys.SESSION_ID, sessionId);
        }

        return context;
    }

    private String extractUserId(Authentication auth) {
        Object principal = auth.getPrincipal();

        if (principal instanceof OidcUser oidcUser) {
            return oidcUser.getSubject();
        }

        return null;
    }

    private String extractUsername(Authentication auth) {
        Object principal = auth.getPrincipal();

        if (principal instanceof OidcUser oidcUser) {
            String preferredUsername = oidcUser.getPreferredUsername();
            if (preferredUsername != null) {
                return preferredUsername;
            }
        }

        return auth.getName();
    }

    private String extractSessionId(Authentication auth) {
        Object principal = auth.getPrincipal();

        if (principal instanceof OidcUser oidcUser) {
            return oidcUser.getClaimAsString("sid");
        }

        return null;
    }
}
