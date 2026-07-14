package com.ids.keycloak.security.config;

/**
 * Realm 역할과 Client 역할을 Spring 권한({@code GrantedAuthority})으로 매핑하는 방식을 정의하는
 * 열거형입니다.
 *
 * <p><b>보안 Advisory 7 (CWE-863) 대응:</b> 과거에는 {@code realm_access.roles}와
 * {@code resource_access.{clientId}.roles}가 모두 동일한 {@code ROLE_<역할명>}으로 변환되어,
 * 동명의 realm 역할과 client 역할을 구분할 수 없었습니다. 이로 인해 realm 역할 보유자가 client 전용
 * 인가 검사(예: {@code hasRole("ADMIN")})를 의도치 않게 통과할 수 있었습니다.</p>
 *
 * <p>{@link #SEPARATE_NAMESPACE}가 기본값이며, realm 역할과 client 역할을 서로 다른 접두사로
 * 분리해 이 문제를 원천 차단합니다. {@link #LEGACY_MERGED}는 과거(취약) 동작이 반드시 필요한
 * 마이그레이션 기간에만 명시적으로 사용하는 호환용 옵션입니다.</p>
 *
 * <pre>
 * keycloak:
 *   security:
 *     role-mapping:
 *       mode: SEPARATE_NAMESPACE   # 기본값. 생략 가능.
 * </pre>
 */
public enum RoleMappingMode {

    /**
     * {@code realm_access.roles}만 추출합니다 (client 역할은 무시). 단일 소스만 사용하므로 이름
     * 충돌 위험이 없어 {@code ROLE_<역할명>} 형태를 그대로 사용합니다.
     */
    REALM_ONLY,

    /**
     * {@code resource_access.{clientId}.roles}만 추출합니다 (realm 역할은 무시, 대상 client는
     * 호출 시 전달된 clientId). 단일 소스만 사용하므로 이름 충돌 위험이 없어 {@code ROLE_<역할명>}
     * 형태를 그대로 사용합니다.
     */
    CLIENT_ONLY,

    /**
     * Realm 역할과 Client 역할을 모두 추출하되, 서로 다른 접두사로 네임스페이스를 분리합니다.
     * <b>기본값(보안 권장)</b>입니다.
     * <p>예: {@code realm_access.roles: ["ADMIN"]} → {@code ROLE_REALM_ADMIN},
     * {@code resource_access.target-client.roles: ["ADMIN"]} → {@code ROLE_CLIENT_TARGET_CLIENT_ADMIN}
     * (clientId의 영숫자가 아닌 문자는 {@code _}로 치환 후 대문자화됩니다).</p>
     */
    SEPARATE_NAMESPACE,

    /**
     * Realm 역할과 Client 역할을 모두 추출하며, 과거 동작과 동일하게 {@code ROLE_<역할명>}로
     * 병합합니다.
     * <p><b>경고:</b> 동명의 realm/client 역할을 구분할 수 없어 CWE-863(잘못된 인가)에 노출됩니다.
     * 마이그레이션 기간 동안 하위 호환이 반드시 필요한 경우에만 명시적으로 사용하고, 애플리케이션의
     * {@code hasRole(...)}/{@code hasAuthority(...)} 검사를 {@link #SEPARATE_NAMESPACE} 기준으로
     * 갱신한 뒤 가능한 빨리 전환하세요.</p>
     */
    LEGACY_MERGED
}
