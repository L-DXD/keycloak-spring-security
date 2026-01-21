package com.ids.keycloak.security.converter;

import com.ids.keycloak.security.exception.AuthorityMappingException;
import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Keycloak에서 발급된 JWT를 Spring Security의 {@link JwtAuthenticationToken}으로 변환하는 클래스.
 * <p>
 * JWT의 클레임에서 사용자 이름과 역할(role) 정보를 추출하여 인증 객체를 생성합니다.
 * - 사용자 이름: 'preferred_username' 클레임 사용
 * - 역할: 'realm_access'와 'resource_access' 클레임에서 추출하여 'ROLE_' 접두사를 붙여 매핑
 */
public class KeycloakJwtAuthenticationConverter implements Converter<Jwt, JwtAuthenticationToken> {

    private static final String REALM_ACCESS_CLAIM = "realm_access";
    private static final String RESOURCE_ACCESS_CLAIM = "resource_access";
    private static final String ROLES_CLAIM = "roles";
    private static final String ROLE_PREFIX = "ROLE_";
    private static final String USERNAME_CLAIM = "preferred_username";

    private final String clientId;

    /**
     * 지정된 클라이언트 ID를 사용하여 Converter를 생성합니다.
     *
     * @param clientId 'resource_access' 클레임에서 역할을 추출할 대상 클라이언트 ID
     */
    public KeycloakJwtAuthenticationConverter(String clientId) {
        this.clientId = clientId;
    }

    /**
     * JWT를 {@link JwtAuthenticationToken}으로 변환합니다.
     *
     * @param jwt 변환할 JWT
     * @return 변환된 {@link JwtAuthenticationToken}
     */
    @Override
    public JwtAuthenticationToken convert(@NonNull Jwt jwt) {
        Collection<GrantedAuthority> authorities = extractRoles(jwt);
        String principalClaimValue = jwt.getClaimAsString(USERNAME_CLAIM);
        return new JwtAuthenticationToken(jwt, authorities, principalClaimValue);
    }

    /**
     * JWT에서 'realm_access'와 'resource_access' 클레임을 조합하여 역할 목록을 추출합니다.
     * <p>
     * - realm 역할과 특정 클라이언트 ID에 해당하는 client 역할을 모두 포함합니다.
     * - 역할 목록에 null이 포함된 경우 안전하게 무시합니다.
     * - 각 역할에는 'ROLE_' 접두사가 추가됩니다.
     *
     * @param jwt 역할 정보를 추출할 JWT
     * @return {@link GrantedAuthority}의 컬렉션
     * @throws AuthorityMappingException 역할 매핑 중 오류 발생 시
     */
    private Collection<GrantedAuthority> extractRoles(Jwt jwt) {
        Map<String, Object> realmAccess = jwt.getClaimAsMap(REALM_ACCESS_CLAIM);
        Map<String, Object> resourceAccess = jwt.getClaimAsMap(RESOURCE_ACCESS_CLAIM);

        Stream<String> realmRoles = Stream.empty();
        if (realmAccess != null && realmAccess.get(ROLES_CLAIM) instanceof List) {
            realmRoles = ((List<String>) realmAccess.get(ROLES_CLAIM)).stream();
        }

        Stream<String> clientRoles = Stream.empty();
        if (clientId != null && resourceAccess != null && resourceAccess.get(clientId) instanceof Map) {
            Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get(clientId);
            if (clientAccess.get(ROLES_CLAIM) instanceof List) {
                clientRoles = ((List<String>) clientAccess.get(ROLES_CLAIM)).stream();
            }
        }

        try {
            return Stream.concat(realmRoles, clientRoles)
                .filter(Objects::nonNull)
                .map(role -> new SimpleGrantedAuthority(ROLE_PREFIX + role))
                .collect(Collectors.toSet());
        } catch (Exception e) {
            throw new AuthorityMappingException();
        }
    }
}
