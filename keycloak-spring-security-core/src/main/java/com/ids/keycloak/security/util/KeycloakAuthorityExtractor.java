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

    /** 선행/후행 {@code _} 제거용 Pattern. {@code String.replaceAll(String, ...)}은 호출마다 정규식을
     *  새로 컴파일하므로, 역할이 많은 토큰에서 반복 호출되지 않도록 static 상수로 1회만 컴파일합니다. */
    private static final Pattern LEADING_TRAILING_UNDERSCORE = Pattern.compile("^_+|_+$");

    /**
     * {@link #extract(Map, String)} 오버로드가 공유하는 기본 역할 매핑 설정입니다.
     *
     * <p><b>불변 계약(mutate 금지):</b> {@link KeycloakRoleMappingProperties}는 Spring
     * {@code @ConfigurationProperties} relaxed 바인딩을 위해 {@code @Setter}를 노출하는 가변
     * 클래스이지만, 이 인스턴스는 클래스 로더 전체에서 공유되는 프로세스 전역 기본값이므로 세터를
     * 호출해 상태를 바꿔서는 안 됩니다. 세터를 호출하면 이 유틸리티를 사용하는 모든 호출자(스레드)에
     * 영향을 주는 전역 상태 변경이 되어 스레드 안전성을 해칩니다. 커스텀 설정이 필요하면 새
     * {@link KeycloakRoleMappingProperties} 인스턴스를 만들어
     * {@link #extract(Map, String, KeycloakRoleMappingProperties)}에 전달하세요.</p>
     */
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
     *
     * <p><b>대소문자 비대칭(의도된 설계):</b> 역할명({@code role})은 Keycloak이 내려준 원본 대소문자를
     * 그대로 사용하지만, clientId 세그먼트는 {@link #normalizeClientId(String)}에 의해 항상
     * 대문자로 변환됩니다. 이는 의도적인 비대칭입니다 — 역할명은 {@link RoleMappingMode#REALM_ONLY},
     * {@link RoleMappingMode#CLIENT_ONLY}, {@link RoleMappingMode#LEGACY_MERGED}를 포함한 모든
     * 모드에서 한 번도 대소문자를 변환한 적이 없는 값이며, Keycloak 관리자가 정의한 역할 식별자
     * 그대로를 {@code hasRole(...)}/{@code hasAuthority(...)} 검사에 노출해야 사용자가 Keycloak
     * Admin Console에서 보는 이름과 애플리케이션 코드의 이름이 항상 일치합니다. 반면 clientId는
     * 역할의 identity가 아니라 네임스페이스를 구성하기 위한 구조적 식별자 세그먼트일 뿐이므로,
     * 가독성이 좋고 안정적인 형태(대문자 스네이크케이스)로 정규화해도 참조 대상이 바뀌지 않습니다.
     * 역할명까지 대문자화하도록 통일하면 이미 breaking change인 Advisory 7 위에 추가로 기존
     * REALM_ONLY/CLIENT_ONLY/LEGACY_MERGED 사용자의 {@code hasRole(...)} 대소문자 일치 여부까지
     * 깨뜨릴 위험이 있어 채택하지 않았습니다.</p>
     */
    private static Set<GrantedAuthority> extractSeparateNamespace(
        Map<String, Object> claims, String clientId, KeycloakRoleMappingProperties mapping) {
        String realmPrefix = mapping.getRealmRolePrefix() != null
            ? mapping.getRealmRolePrefix() : "ROLE_REALM_";
        String clientPrefix = mapping.getClientRolePrefix() != null
            ? mapping.getClientRolePrefix() : "ROLE_CLIENT_";
        // 역할 개수와 무관하게 clientId 정규화는 1회만 계산해 재사용한다(Low #3: 역할마다 반복 호출 방지).
        String normalizedClientId = normalizeClientId(clientId);

        Stream<GrantedAuthority> realmAuthorities = extractRealmRoles(claims)
            .filter(Objects::nonNull)
            .map(role -> new SimpleGrantedAuthority(realmPrefix + role));

        Stream<GrantedAuthority> clientAuthorities = extractClientRoles(claims, clientId)
            .filter(Objects::nonNull)
            .map(role -> new SimpleGrantedAuthority(clientPrefix + normalizedClientId + "_" + role));

        return Stream.concat(realmAuthorities, clientAuthorities).collect(Collectors.toSet());
    }

    /**
     * clientId를 권한 문자열의 네임스페이스 세그먼트로 안전하게 사용할 수 있도록 정규화합니다.
     * 영숫자가 아닌 문자(예: {@code -}, {@code .})는 {@code _}로 치환하고, 선행/후행 {@code _}는
     * 제거한 뒤 대문자로 변환합니다. 예: {@code target-client} → {@code TARGET_CLIENT}.
     *
     * <p><b>정규화 손실 가능성(허용된 트레이드오프):</b> 영숫자가 아닌 문자를 모두 {@code _}로
     * 치환하므로 서로 다른 clientId가 동일한 정규화 결과로 충돌할 수 있습니다. 예:
     * {@code target-client}와 {@code target.client}는 둘 다 {@code TARGET_CLIENT}로 정규화됩니다.
     * 단일 애플리케이션은 보통 자신의 clientId 하나만을 대상으로 이 메서드를 호출하므로(호출 시
     * 전달되는 clientId는 해당 애플리케이션에 고정) 실질적으로 무해하지만, 한 프로세스가 이름이
     * 이렇게 충돌하는 여러 clientId의 역할을 동시에 추출·병기해야 하는 드문 경우라면 이 정규화만으로는
     * 두 clientId를 구분할 수 없다는 점을 인지하고 있어야 합니다.</p>
     *
     * <p>이 메서드는 {@link #extractSeparateNamespace}에서 clientId가 주어질 때마다(=역할 수와
     * 무관하게) 1회만 호출되도록 호출부에서 결과를 재사용합니다. clientId가 null/공백인 경우는
     * {@code extractClientRoles}가 항상 빈 스트림을 반환해 client 권한 자체가 생성되지 않지만,
     * 방어적으로 {@code "UNKNOWN"}을 반환합니다.</p>
     */
    private static String normalizeClientId(String clientId) {
        if (clientId == null || clientId.isBlank()) {
            return "UNKNOWN";
        }
        String normalized = NON_ALPHANUMERIC.matcher(clientId.trim()).replaceAll("_");
        normalized = LEADING_TRAILING_UNDERSCORE.matcher(normalized).replaceAll("");
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
