package com.ids.keycloak.security.util;

import com.ids.keycloak.security.exception.TokenBindingException;
import java.util.List;
import lombok.experimental.UtilityClass;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * ID Token과 Access Token(UserInfo)이 동일 사용자·동일 Client에 발급되었는지 검증하는 공통 컴포넌트입니다.
 * Servlet({@code keycloak-spring-security-web})과 WebFlux({@code keycloak-spring-security-webflux})
 * 양쪽의 인증 처리(Provider/ReactiveAuthenticationManager)에서 동일하게 재사용합니다.
 *
 * <p><b>보안 Advisory 1 대응 배경:</b> 이전에는 ID Token {@code sub}를 서명 검증 없이 파싱해 Principal로 사용하고,
 * ID Token과 Access Token(UserInfo)의 sub/aud/azp 일치 여부를 검사하지 않아 서로 다른 사용자·Client의
 * 토큰을 조합해도 인증이 성공하는 Identity Confusion이 가능했습니다.</p>
 *
 * <p>여기서 받는 {@link Jwt}는 반드시 서명 검증을 통과한(Spring {@code JwtDecoder}/{@code ReactiveJwtDecoder}로
 * 디코딩된) 결과여야 합니다. {@code iss}(issuer)는 해당 디코더 생성 시
 * {@code JwtValidators.createDefaultWithIssuer(issuerUri)}로 이미 검증되므로 이 클래스에서 별도로
 * 재검증하지 않습니다.</p>
 *
 * <p><b>Access Token의 {@code aud} 검증에 대한 설계 결정:</b> Keycloak Access Token은 클라이언트별
 * Audience 프로토콜 매퍼가 설정되어 있지 않으면 기본적으로 요청 Client의 client-id를 {@code aud}에
 * 포함하지 않는 경우가 흔합니다(예: {@code aud=["account"]}). 따라서 Access Token에는 {@code aud}
 * 포함 여부를 강제하지 않고, {@code azp}(있는 경우에 한해)만 검증합니다. ID Token은 OIDC Core 스펙상
 * {@code aud}에 client-id가 항상 포함되어야 하므로 이 클래스에서 엄격히 강제합니다.</p>
 */
@UtilityClass
public class TokenBindingValidator {

    /** Authorized Party 클레임 이름 (OIDC Core 1.0). */
    private static final String CLAIM_AZP = "azp";

    /**
     * ID Token의 {@code aud}에 client-id가 포함되어 있는지, {@code azp}가 있다면 client-id와 일치하는지
     * 검증합니다. OIDC Core 스펙상 ID Token의 {@code aud}는 항상 client-id를 포함해야 하므로 엄격히 검증합니다.
     *
     * @param idToken  서명 검증이 완료된 ID Token {@link Jwt}
     * @param clientId 이 애플리케이션의 OIDC client-id
     * @throws TokenBindingException aud 미포함 또는 azp 불일치 시
     */
    public static void validateIdTokenBinding(Jwt idToken, String clientId) {
        if (clientId == null || clientId.isBlank()) {
            // client-id 미설정 환경(이론상 발생하지 않음) — 방어적으로 검증 스킵
            return;
        }

        List<String> audience = idToken.getAudience();
        if (audience == null || !audience.contains(clientId)) {
            throw new TokenBindingException(
                "ID Token의 aud 클레임에 client-id(" + clientId + ")가 포함되어 있지 않습니다.");
        }

        validateAzp(idToken, clientId, "ID Token");
    }

    /**
     * Access Token의 {@code azp}가 있는 경우에 한해 client-id와 일치하는지 검증합니다.
     * Keycloak Access Token은 Audience 매퍼 설정에 따라 {@code aud}에 client-id를 포함하지 않는 경우가
     * 흔하므로 {@code aud} 포함 여부는 강제하지 않습니다.
     *
     * @param accessToken 서명 검증이 완료된 Access Token {@link Jwt} (JWT 형식일 때만 호출)
     * @param clientId    이 애플리케이션의 OIDC client-id
     * @throws TokenBindingException azp가 있는데 client-id와 불일치할 시
     */
    public static void validateAccessTokenAzp(Jwt accessToken, String clientId) {
        if (clientId == null || clientId.isBlank()) {
            return;
        }
        validateAzp(accessToken, clientId, "Access Token");
    }

    private static void validateAzp(Jwt token, String clientId, String tokenLabel) {
        String azp = token.getClaimAsString(CLAIM_AZP);
        if (azp != null && !azp.equals(clientId)) {
            throw new TokenBindingException(
                tokenLabel + "의 azp 클레임(" + azp + ")이 client-id(" + clientId + ")와 일치하지 않습니다.");
        }
    }

    /**
     * ID Token의 subject와 UserInfo의 subject가 동일한지 검증합니다.
     * UserInfo가 없으면(조회 실패 시 빈 권한 정책, {@code require-user-info=false}) 검증을 스킵합니다 —
     * 기존 정책과 회귀 없이 공존합니다.
     *
     * @param idTokenSubject  서명 검증이 완료된 ID Token에서 추출한 subject
     * @param userInfoSubject UserInfo 응답의 subject (조회 실패/미사용 시 {@code null})
     * @throws TokenBindingException 두 subject가 다를 경우
     */
    public static void validateSubjectBinding(String idTokenSubject, String userInfoSubject) {
        if (userInfoSubject == null) {
            return;
        }
        if (!userInfoSubject.equals(idTokenSubject)) {
            throw new TokenBindingException(
                "ID Token의 subject(" + idTokenSubject + ")와 UserInfo의 subject(" + userInfoSubject
                    + ")가 일치하지 않습니다.");
        }
    }
}
