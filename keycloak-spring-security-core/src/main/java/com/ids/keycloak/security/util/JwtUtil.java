package com.ids.keycloak.security.util;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
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


    /**
     * JWT 토큰에서 서명 검증 없이 클레임만 추출합니다.
     * <p>
     * 온라인 검증(Keycloak Introspect)을 사용하는 경우, 토큰의 유효성은
     * Keycloak에서 검증하므로 여기서는 클레임 정보만 파싱합니다.
     * </p>
     *
     * @param token JWT 토큰 문자열
     * @return 클레임 맵 (파싱 실패 시 빈 맵 반환)
     */
    public static Map<String, Object> parseClaimsWithoutValidation(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            return claimsSet.getClaims();
        } catch (ParseException e) {
            return Collections.emptyMap();
        }
    }

    /**
     * JWT 토큰에서 서명 검증 없이 subject(사용자 ID)를 추출합니다.
     *
     * @param token JWT 토큰 문자열
     * @return subject 값 (파싱 실패 시 null 반환)
     */
    public static String parseSubjectWithoutValidation(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            return signedJWT.getJWTClaimsSet().getSubject();
        } catch (ParseException e) {
            return null;
        } catch (NullPointerException e){
            return null;
        }
    }
}
