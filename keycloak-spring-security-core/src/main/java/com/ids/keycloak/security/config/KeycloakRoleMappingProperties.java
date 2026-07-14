package com.ids.keycloak.security.config;

import lombok.Getter;
import lombok.Setter;

/**
 * Keycloak Realm/Client 역할(Role)을 Spring {@code GrantedAuthority}로 매핑하는 방식을 설정하는
 * Properties 클래스입니다.
 *
 * <p><b>보안 Advisory 7 대응 (CWE-863, breaking change):</b> 과거에는 {@code realm_access.roles}와
 * {@code resource_access.{clientId}.roles}가 모두 동일한 {@code ROLE_<역할명>}으로 변환되어,
 * 동명의 realm 역할과 client 역할을 구분할 수 없었습니다. 기본값은
 * {@link RoleMappingMode#SEPARATE_NAMESPACE}로 두 역할군을 서로 다른 네임스페이스로 분리합니다
 * (secure by default). 과거 동작이 반드시 필요한 경우에만
 * {@link RoleMappingMode#LEGACY_MERGED}로 명시적으로 전환하세요.</p>
 *
 * <p><b>마이그레이션 예시</b> (client-id={@code target-client}):
 * <pre>
 * # 기본값(권장) — 별도 설정 불필요
 * # realm_access.roles: ["ADMIN"]                      -&gt; ROLE_REALM_ADMIN
 * # resource_access.target-client.roles: ["ADMIN"]      -&gt; ROLE_CLIENT_TARGET_CLIENT_ADMIN
 *
 * # 과거(취약) 동작이 마이그레이션 기간 동안 반드시 필요한 경우에만 명시적으로 설정
 * keycloak:
 *   security:
 *     role-mapping:
 *       mode: LEGACY_MERGED   # realm/client 역할 모두 ROLE_&lt;역할명&gt;으로 병합 (구분 불가, 비권장)
 * </pre>
 * </p>
 */
@Getter
@Setter
public class KeycloakRoleMappingProperties {

    /**
     * Realm/Client 역할 추출·네임스페이스 전략 (기본값: {@link RoleMappingMode#SEPARATE_NAMESPACE}).
     */
    private RoleMappingMode mode = RoleMappingMode.SEPARATE_NAMESPACE;

    /**
     * {@link RoleMappingMode#SEPARATE_NAMESPACE}일 때 Realm 역할에 붙일 접두사
     * (기본값: {@code ROLE_REALM_}).
     */
    private String realmRolePrefix = "ROLE_REALM_";

    /**
     * {@link RoleMappingMode#SEPARATE_NAMESPACE}일 때 Client 역할에 붙일 접두사
     * (기본값: {@code ROLE_CLIENT_}). 실제 권한 문자열은
     * {@code <clientRolePrefix><정규화된 clientId>_<역할명>} 형태입니다.
     */
    private String clientRolePrefix = "ROLE_CLIENT_";
}
