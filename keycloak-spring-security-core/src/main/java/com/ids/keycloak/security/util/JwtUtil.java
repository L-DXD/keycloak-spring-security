package com.ids.keycloak.security.util;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import lombok.experimental.UtilityClass;

/**
 * JWT 클레임 처리를 위한 유틸리티 클래스입니다.
 */
@UtilityClass
public class JwtUtil {

    public static final String CLAIM_RESOURCE_ACCESS = "resource_access";
    public static final String CLAIM_ROLES = "roles";

    /**
     * JWT 클레임에서 특정 클라이언트의 역할(roles) 목록을 추출합니다.
     *
     * @param claims   JWT 클레임 맵
     * @param clientId 역할을 추출할 대상 클라이언트 ID
     * @return 역할 목록 (없으면 빈 리스트 반환)
     */
    @SuppressWarnings("unchecked")
    public static List<String> extractRoles(Map<String, Object> claims, String clientId) {
        Object resourceAccessObj = claims.get(CLAIM_RESOURCE_ACCESS);
        if (!(resourceAccessObj instanceof Map)) {
            return Collections.emptyList();
        }

        Map<String, Object> resourceAccess = (Map<String, Object>) resourceAccessObj;
        Object clientAccessObj = resourceAccess.get(clientId);
        if (!(clientAccessObj instanceof Map)) {
            return Collections.emptyList();
        }

        Map<String, Object> clientAccess = (Map<String, Object>) clientAccessObj;
        Object rolesObj = clientAccess.get(CLAIM_ROLES);
        if (rolesObj instanceof List) {
            return (List<String>) rolesObj;
        }

        return Collections.emptyList();
    }
}
