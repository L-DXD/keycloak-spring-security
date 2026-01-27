package com.ids.keycloak.security.util;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Keycloak 클레임에서 권한(GrantedAuthority)을 추출하는 유틸리티 클래스입니다.
 * <p>
 * realm_access.roles와 resource_access.{clientId}.roles에서 역할을 추출하여
 * ROLE_ 접두사를 붙인 GrantedAuthority로 변환합니다.
 * </p>
 */
public final class KeycloakAuthorityExtractor {

    private static final String REALM_ACCESS_CLAIM = "realm_access";
    private static final String RESOURCE_ACCESS_CLAIM = "resource_access";
    private static final String ROLES_CLAIM = "roles";
    private static final String ROLE_PREFIX = "ROLE_";

    private KeycloakAuthorityExtractor() {
        // 유틸리티 클래스 - 인스턴스화 방지
    }

    /**
     * 클레임에서 권한 정보를 추출합니다.
     *
     * @param claims   클레임 맵 (ID Token 또는 UserInfo)
     * @param clientId 클라이언트 ID (resource_access에서 역할 추출 시 사용, null 가능)
     * @return GrantedAuthority 컬렉션
     */
    public static Collection<GrantedAuthority> extract(Map<String, Object> claims, String clientId) {
        if (claims == null || claims.isEmpty()) {
            return Collections.emptySet();
        }

        Stream<String> realmRoles = extractRealmRoles(claims);
        Stream<String> clientRoles = extractClientRoles(claims, clientId);

        return Stream.concat(realmRoles, clientRoles)
            .filter(Objects::nonNull)
            .map(role -> new SimpleGrantedAuthority(ROLE_PREFIX + role))
            .collect(Collectors.toSet());
    }

    /**
     * realm_access.roles에서 Realm 레벨 역할을 추출합니다.
     */
    @SuppressWarnings("unchecked")
    private static Stream<String> extractRealmRoles(Map<String, Object> claims) {
        Object realmAccess = claims.get(REALM_ACCESS_CLAIM);
        if (realmAccess instanceof Map) {
            Object roles = ((Map<String, Object>) realmAccess).get(ROLES_CLAIM);
            if (roles instanceof List) {
                return ((List<String>) roles).stream();
            }
        }
        return Stream.empty();
    }

    /**
     * resource_access.{clientId}.roles에서 Client 레벨 역할을 추출합니다.
     */
    @SuppressWarnings("unchecked")
    private static Stream<String> extractClientRoles(Map<String, Object> claims, String clientId) {
        if (clientId == null) {
            return Stream.empty();
        }

        Object resourceAccess = claims.get(RESOURCE_ACCESS_CLAIM);
        if (resourceAccess instanceof Map) {
            Object clientAccess = ((Map<String, Object>) resourceAccess).get(clientId);
            if (clientAccess instanceof Map) {
                Object roles = ((Map<String, Object>) clientAccess).get(ROLES_CLAIM);
                if (roles instanceof List) {
                    return ((List<String>) roles).stream();
                }
            }
        }
        return Stream.empty();
    }
}
