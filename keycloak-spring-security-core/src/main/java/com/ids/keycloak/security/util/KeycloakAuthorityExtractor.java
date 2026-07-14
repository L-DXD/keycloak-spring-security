package com.ids.keycloak.security.util;

import com.ids.keycloak.security.config.KeycloakRoleMappingProperties;
import com.ids.keycloak.security.config.RoleMappingMode;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Keycloak 클레임에서 권한(GrantedAuthority)을 추출하는 유틸리티 클래스입니다.
 * <p>
 * realm_access.roles와 resource_access.{clientId}.roles에서 역할을 추출하여
 * GrantedAuthority로 변환합니다.
 * </p>
 *
 * <p><b>보안 Advisory 7 대응 (CWE-863, breaking change):</b> 과거에는 realm 역할과 client 역할이
 * 모두 동일한 {@code ROLE_<역할명>}으로 변환되어, 동명 역할(예: {@code ADMIN})을 가진 realm
 * 사용자가 client 전용 인가 검사({@code hasRole("ADMIN")})를 의도치 않게 통과할 수 있었습니다.</p>
 *
 * <p>기본값은 {@link RoleMappingMode#SEPARATE_NAMESPACE}로, realm/client 역할을 별도 접두사로
 * 분리합니다:
 * <ul>
 *   <li>{@code realm_access.roles: ["ADMIN"]} → {@code ROLE_REALM_ADMIN}</li>
 *   <li>{@code resource_access.target-client.roles: ["ADMIN"]} → {@code ROLE_CLIENT_TARGET_CLIENT_ADMIN}
 *       (clientId의 영숫자가 아닌 문자는 {@code _}로 치환 후 대문자화)</li>
 * </ul>
 * 과거(취약) 동작이 마이그레이션 기간 동안 반드시 필요하면 {@link RoleMappingMode#LEGACY_MERGED}를
 * 명시적으로 설정하세요 ({@code keycloak.security.role-mapping.mode=LEGACY_MERGED}).
 * <b>주의:</b> 인자가 2개인 {@link #extract(Map, String)} 오버로드도 이 변경의 영향을 받습니다 —
 * 과거에는 병합(merged) 동작이었으나, 이제 기본값인 분리(separate-namespace) 동작을 사용합니다.
 * 과거 동작이 필요하면 {@link #extract(Map, String, KeycloakRoleMappingProperties)}에
 * {@code mode=LEGACY_MERGED}로 설정한 {@link KeycloakRoleMappingProperties}를 명시적으로
 * 전달하세요.</p>
 */
public final class KeycloakAuthorityExtractor {

    private static final String REALM_ACCESS_CLAIM = "realm_access";
    private static final String RESOURCE_ACCESS_CLAIM = "resource_access";
    private static final String ROLES_CLAIM = "roles";

    /**
     * {@link RoleMappingMode#REALM_ONLY}, {@link RoleMappingMode#CLIENT_ONLY},
     * {@link RoleMappingMode#LEGACY_MERGED}에서 사용하는 접두사. 단일 소스만 추출하는 모드에서는
     * 이름 충돌 위험이 없으므로 과거와 동일한 {@code ROLE_} 접두사를 그대로 사용합니다.
     */
    private static final String LEGACY_ROLE_PREFIX = "ROLE_";

    private static final Pattern NON_ALPHANUMERIC = Pattern.compile("[^A-Za-z0-9]+");

    private static final KeycloakRoleMappingProperties DEFAULT_ROLE_MAPPING =
        new KeycloakRoleMappingProperties();

    private KeycloakAuthorityExtractor() {
        // 유틸리티 클래스 - 인스턴스화 방지
    }

    /**
     * 클레임에서 권한 정보를 추출합니다. 기본 설정({@link RoleMappingMode#SEPARATE_NAMESPACE})을
     * 사용합니다.
     *
     * <p><b>보안 Advisory 7:</b> 이 오버로드는 v1.11.0부터 realm/client 역할을 분리된 네임스페이스로
     * 반환합니다(이전 버전은 병합했습니다). 과거 동작이 필요하면
     * {@link #extract(Map, String, KeycloakRoleMappingProperties)}를 {@code LEGACY_MERGED} 모드로
     * 명시적으로 호출하세요.</p>
     *
     * @param claims   클레임 맵 (ID Token 또는 UserInfo)
     * @param clientId 클라이언트 ID (resource_access에서 역할 추출 시 사용, null 가능)
     * @return GrantedAuthority 컬렉션
     * @see #extract(Map, String, KeycloakRoleMappingProperties)
     */
    public static Collection<GrantedAuthority> extract(Map<String, Object> claims, String clientId) {
        return extract(claims, clientId, DEFAULT_ROLE_MAPPING);
    }

    /**
     * 클레임에서 권한 정보를 {@code roleMapping} 설정에 따라 추출합니다.
     *
     * @param claims      클레임 맵 (ID Token 또는 UserInfo)
     * @param clientId    클라이언트 ID (resource_access에서 역할 추출 시 사용, null 가능)
     * @param roleMapping Realm/Client 역할 네임스페이스 전략 (null이면 기본값
     *                    {@link RoleMappingMode#SEPARATE_NAMESPACE} 적용)
     * @return GrantedAuthority 컬렉션
     */
    public static Collection<GrantedAuthority> extract(
        Map<String, Object> claims, String clientId, KeycloakRoleMappingProperties roleMapping) {
        if (claims == null || claims.isEmpty()) {
            return Collections.emptySet();
        }

        KeycloakRoleMappingProperties mapping = roleMapping != null ? roleMapping : DEFAULT_ROLE_MAPPING;
        RoleMappingMode mode = mapping.getMode() != null ? mapping.getMode() : RoleMappingMode.SEPARATE_NAMESPACE;

        return switch (mode) {
            case REALM_ONLY -> extractRealmRoles(claims)
                .filter(Objects::nonNull)
                .map(role -> new SimpleGrantedAuthority(LEGACY_ROLE_PREFIX + role))
                .collect(Collectors.toSet());
            case CLIENT_ONLY -> extractClientRoles(claims, clientId)
                .filter(Objects::nonNull)
                .map(role -> new SimpleGrantedAuthority(LEGACY_ROLE_PREFIX + role))
                .collect(Collectors.toSet());
            case LEGACY_MERGED -> Stream.concat(extractRealmRoles(claims), extractClientRoles(claims, clientId))
                .filter(Objects::nonNull)
                .map(role -> new SimpleGrantedAuthority(LEGACY_ROLE_PREFIX + role))
                .collect(Collectors.toSet());
            case SEPARATE_NAMESPACE -> extractSeparateNamespace(claims, clientId, mapping);
        };
    }

    /**
     * Realm 역할은 {@code realmRolePrefix}, Client 역할은
     * {@code clientRolePrefix + 정규화된 clientId + "_"}로 서로 다른 네임스페이스를 적용해
     * 추출합니다(보안 Advisory 7 기본 동작).
     */
    private static Set<GrantedAuthority> extractSeparateNamespace(
        Map<String, Object> claims, String clientId, KeycloakRoleMappingProperties mapping) {
        String realmPrefix = mapping.getRealmRolePrefix() != null
            ? mapping.getRealmRolePrefix() : "ROLE_REALM_";
        String clientPrefix = mapping.getClientRolePrefix() != null
            ? mapping.getClientRolePrefix() : "ROLE_CLIENT_";

        Stream<GrantedAuthority> realmAuthorities = extractRealmRoles(claims)
            .filter(Objects::nonNull)
            .map(role -> new SimpleGrantedAuthority(realmPrefix + role));

        Stream<GrantedAuthority> clientAuthorities = extractClientRoles(claims, clientId)
            .filter(Objects::nonNull)
            .map(role -> new SimpleGrantedAuthority(clientPrefix + normalizeClientId(clientId) + "_" + role));

        return Stream.concat(realmAuthorities, clientAuthorities).collect(Collectors.toSet());
    }

    /**
     * clientId를 권한 문자열의 네임스페이스 세그먼트로 안전하게 사용할 수 있도록 정규화합니다.
     * 영숫자가 아닌 문자(예: {@code -}, {@code .})는 {@code _}로 치환하고, 선행/후행 {@code _}는
     * 제거한 뒤 대문자로 변환합니다. 예: {@code target-client} → {@code TARGET_CLIENT}.
     *
     * <p>이 메서드는 {@code extractClientRoles}가 최소 1개 이상의 client 역할을 반환했을 때만
     * 호출되므로(스트림이 비어있으면 map 함수가 호출되지 않음), clientId가 null인 경우는 실제로는
     * 도달하지 않지만 방어적으로 {@code "UNKNOWN"}을 반환합니다.</p>
     */
    private static String normalizeClientId(String clientId) {
        if (clientId == null || clientId.isBlank()) {
            return "UNKNOWN";
        }
        String normalized = NON_ALPHANUMERIC.matcher(clientId.trim()).replaceAll("_");
        normalized = normalized.replaceAll("^_+|_+$", "");
        return normalized.isEmpty() ? "UNKNOWN" : normalized.toUpperCase(Locale.ROOT);
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
