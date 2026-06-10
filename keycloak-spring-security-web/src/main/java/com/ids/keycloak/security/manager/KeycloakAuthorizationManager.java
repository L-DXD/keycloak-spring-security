package com.ids.keycloak.security.manager;

import com.ids.keycloak.security.authentication.AccessTokenHolder;
import com.sd.KeycloakClient.dto.KeycloakResponse;
import com.sd.KeycloakClient.dto.auth.KeycloakAuthorizationResult;
import com.sd.KeycloakClient.factory.KeycloakClient;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.web.client.RestClientException;

/**
 * Keycloak Authorization Services를 사용하여 HTTP 요청에 대한 인가를 수행하는
 * {@link AuthorizationManager} 구현체입니다.
 * <p>
 * 다음 인증 타입을 지원합니다:
 * <ul>
 *   <li>{@link AccessTokenHolder} - {@code KeycloakAuthentication}, {@code BasicAuthenticationToken} 등
 *       라이브러리 자체 인증 토큰</li>
 *   <li>{@link BearerTokenAuthentication} - Spring Security OAuth2 Resource Server의 Bearer 토큰 인증</li>
 * </ul>
 * </p>
 *
 * <p><b>인가 결정 캐시 (M-1):</b><br>
 * {@code keycloak.security.authorization.cache.enabled=true}로 설정하면 짧은 TTL 동안
 * 동일 (사용자 이름, 경로, HTTP 메서드) 조합의 인가 결정을 인메모리로 캐시합니다.
 * 기본값은 {@code false}이므로 회귀가 없습니다.
 * </p>
 */
@Slf4j
public class KeycloakAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final KeycloakClient keycloakClient;

    /** 캐시 활성화 여부 (기본 false) */
    private boolean cacheEnabled = false;
    /** 캐시 TTL (밀리초) */
    private long cacheTtlMs = 10_000L;

    /**
     * 인가 결정 캐시 엔트리.
     */
    private record CacheEntry(boolean granted, long expireAt) {
        boolean isExpired() {
            return System.currentTimeMillis() > expireAt;
        }
    }

    /** 캐시 최대 항목 수 (무경계 증가 방지). 초과 시 put 전 만료 엔트리를 일괄 정리합니다. */
    private static final int CACHE_MAX_SIZE = 10_000;

    /** (사용자명+경로+메서드) → 인가 결정 캐시 */
    private final ConcurrentHashMap<String, CacheEntry> decisionCache = new ConcurrentHashMap<>();

    public KeycloakAuthorizationManager(KeycloakClient keycloakClient) {
        this.keycloakClient = keycloakClient;
    }

    /**
     * 인가 결정 캐시를 설정합니다.
     *
     * @param enabled    true이면 캐시 활성화
     * @param ttlSeconds 캐시 TTL (초)
     */
    public void setCacheConfig(boolean enabled, int ttlSeconds) {
        this.cacheEnabled = enabled;
        this.cacheTtlMs = (long) ttlSeconds * 1000;
        if (enabled) {
            log.info("[Authorization] 인가 결정 캐시 활성화: TTL={}초", ttlSeconds);
        }
    }

    /**
     * 현재 인증된 사용자가 요청한 HTTP 리소스에 접근할 수 있는지 Keycloak에 인가 요청을 보냅니다.
     *
     * <p>캐시가 활성화({@code cache.enabled=true})된 경우, 유효한 캐시 엔트리가 있으면
     * Keycloak 호출 없이 캐시된 결정을 반환합니다.</p>
     *
     * @param authentication 현재 인증 정보 공급자
     * @param context        요청 인가 컨텍스트 (HTTP 메서드, 엔드포인트 포함)
     * @return 인가 결과 ({@code true}면 허용, {@code false}면 거부)
     */
    @Override
    public AuthorizationDecision check(
        Supplier<Authentication> authentication,
        RequestAuthorizationContext context
    ) {
        HttpServletRequest request = context.getRequest();
        String method = request.getMethod();
        String endpoint = request.getRequestURI();

        log.debug("[Authorization] 인가 요청 수신: {} {}", method, endpoint);

        Authentication auth = authentication.get();

        if (!auth.isAuthenticated()) {
            log.warn("[Authorization] 미인증 사용자 요청 거부: {} {}", method, endpoint);
            return new AuthorizationDecision(false);
        }

        String accessToken;
        if (auth instanceof AccessTokenHolder holder) {
            log.debug("[Authorization] AccessTokenHolder 인증 타입: {}", auth.getClass().getSimpleName());
            accessToken = holder.getAccessToken();
        } else if (auth instanceof BearerTokenAuthentication bearer) {
            log.debug("[Authorization] BearerTokenAuthentication 인증 타입");
            accessToken = bearer.getToken().getTokenValue();
        } else {
            log.warn("[Authorization] 지원하지 않는 인증 타입 거부: {}", auth.getClass().getSimpleName());
            return new AuthorizationDecision(false);
        }

        // 캐시 조회 (활성화 시)
        if (cacheEnabled) {
            String cacheKey = buildCacheKey(auth.getName(), endpoint, method);
            CacheEntry cached = decisionCache.get(cacheKey);
            if (cached != null && !cached.isExpired()) {
                log.debug("[Authorization] 캐시 히트: {} {} → {}", method, endpoint, cached.granted() ? "허용" : "거부");
                return new AuthorizationDecision(cached.granted());
            }
            // 만료된 엔트리 제거
            if (cached != null) {
                decisionCache.remove(cacheKey, cached);
            }
        }

        log.debug("[Authorization] Keycloak에 인가 요청...");

        KeycloakResponse<KeycloakAuthorizationResult> response;
        try {
            response = keycloakClient.auth().authorization(accessToken, endpoint, method);
        } catch (RestClientException e) {
            log.warn("[Authorization] Keycloak 인가 요청 실패 (통신 오류). 거부 처리: {} {} - {}", method, endpoint, e.getMessage());
            return new AuthorizationDecision(false);
        }

        KeycloakAuthorizationResult result = response.getBody().orElse(null);

        if (result == null) {
            log.warn("[Authorization] Keycloak 인가 응답 본문 없음. 거부 처리: {} {}", method, endpoint);
            return new AuthorizationDecision(false);
        }

        boolean granted = result.isGranted();
        log.debug("[Authorization] Keycloak 인가 결과: {} - {} {}", granted ? "허용" : "거부", method, endpoint);

        // 캐시 저장 (활성화 시)
        if (cacheEnabled) {
            String cacheKey = buildCacheKey(auth.getName(), endpoint, method);
            // 상한 초과 시 만료 엔트리 정리 후 저장 (무경계 증가 방지, N-4)
            if (decisionCache.size() >= CACHE_MAX_SIZE) {
                evictExpiredEntries();
            }
            decisionCache.put(cacheKey, new CacheEntry(granted, System.currentTimeMillis() + cacheTtlMs));
        }

        return new AuthorizationDecision(granted);
    }

    /**
     * 캐시 키를 생성합니다. 사용자명, 경로, HTTP 메서드의 조합입니다.
     */
    private static String buildCacheKey(String username, String endpoint, String method) {
        return username + "|" + method + "|" + endpoint;
    }

    /**
     * 만료된 캐시 엔트리를 일괄 제거합니다.
     *
     * <p>캐시 크기가 {@link #CACHE_MAX_SIZE}에 도달했을 때 호출됩니다.
     * 만료된 엔트리만 제거하므로 유효한 캐시는 유지됩니다.</p>
     */
    private void evictExpiredEntries() {
        int removed = 0;
        for (Map.Entry<String, CacheEntry> entry : decisionCache.entrySet()) {
            if (entry.getValue().isExpired()) {
                decisionCache.remove(entry.getKey(), entry.getValue());
                removed++;
            }
        }
        log.debug("[Authorization] 캐시 정리 완료: {} 개 만료 엔트리 제거 (현재 크기: {})",
            removed, decisionCache.size());
    }
}
