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

    /**
     * 오설정으로 인한 Advisory 7(CWE-863) 재현을 막기 위한 기동 시 검증입니다.
     *
     * <p>{@link RoleMappingMode#SEPARATE_NAMESPACE}(기본값)에서 {@code realmRolePrefix}와
     * {@code clientRolePrefix}가 공백이거나 서로 동일하면 realm 역할과 client 역할이 결국 같은
     * 접두사로 귀결되어 이 클래스가 존재하는 이유(네임스페이스 분리)가 무력화됩니다. client 권한은
     * 통상 clientId 세그먼트가 추가로 붙어 대부분의 경우 우연히 구분되지만, "동일 접두사 + 겹치는
     * 역할명" 조합에서는 여전히 충돌할 수 있으므로 이를 조용히 허용하지 않고 기동 실패로 즉시
     * 드러냅니다.</p>
     *
     * @throws IllegalStateException 접두사가 공백이거나 서로 동일한 경우
     */
    public void validate() {
        if (mode != RoleMappingMode.SEPARATE_NAMESPACE) {
            return;
        }

        boolean realmBlank = realmRolePrefix == null || realmRolePrefix.isBlank();
        boolean clientBlank = clientRolePrefix == null || clientRolePrefix.isBlank();
        if (realmBlank || clientBlank) {
            throw new IllegalStateException(
                "keycloak.security.role-mapping: mode=SEPARATE_NAMESPACE에서는 realm-role-prefix/"
                    + "client-role-prefix를 공백으로 둘 수 없습니다 (realmRolePrefix=" + realmRolePrefix
                    + ", clientRolePrefix=" + clientRolePrefix + "). 접두사가 없으면 realm 역할과 "
                    + "client 역할의 네임스페이스가 분리되지 않아 Advisory 7(CWE-863)이 재현됩니다.");
        }

        if (realmRolePrefix.equals(clientRolePrefix)) {
            throw new IllegalStateException(
                "keycloak.security.role-mapping: mode=SEPARATE_NAMESPACE에서 realm-role-prefix와 "
                    + "client-role-prefix가 동일합니다 (\"" + realmRolePrefix + "\"). 동일 접두사와 "
                    + "겹치는 역할명 조합에서 realm 역할과 client 역할을 구분할 수 없게 되어 "
                    + "Advisory 7(CWE-863)이 재현될 수 있으므로 서로 다른 접두사를 설정하세요.");
        }
    }
}
