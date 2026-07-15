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
 *
 * <p><b>보안 패치 2.0.1(외부 검토 High #1) 대응 배경:</b> Advisory 1 도입 당시에는 Access Token에
 * 대해 {@code azp}만 검증하고 {@code sub}는 UserInfo를 통해서만 간접 확인했습니다({@link
 * #validateSubjectBinding}). 그런데 {@code require-user-info=false}(기본값)이고 UserInfo 조회가
 * 실패하면 이 간접 sub 검증 자체가 스킵되어, 같은 Client에 발급된 서로 다른 사용자의 ID Token과
 * Access Token 조합(Principal=A, 토큰=B)이 azp 일치만으로 통과할 수 있었습니다. 이를 막기 위해
 * {@link #validateAccessTokenSubject}를 추가해 JWT Access Token의 {@code sub}를 ID Token의
 * {@code sub}와 UserInfo 가용성과 무관하게 직접 비교합니다.</p>
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
     * <p>이 메서드는 Client 결합(azp)만 검증합니다. 사용자 결합(sub)은 {@link #validateAccessTokenSubject}로
     * 별도 검증해야 하며, 호출부는 이 메서드에 이어서 반드시 함께 호출해야 합니다(2.0.1 패치).</p>
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

    /**
     * JWT 형식인 Access Token의 {@code sub}가 ID Token의 {@code sub}와 동일한지 직접 비교합니다.
     *
     * <p><b>보안 패치 2.0.1(외부 검토 High #1) 대응:</b> 기존에는 Access Token에 대해 {@code azp}만
     * 검증하고 {@code sub}는 UserInfo 조회 결과를 통해서만 간접 확인했습니다({@link
     * #validateSubjectBinding}). {@code require-user-info=false}(기본값)에서 UserInfo 조회가 실패하면
     * 그 간접 검증 자체가 스킵되어, 사용자 A의 ID Token과 같은 Client에서 발급된 사용자 B의 Access Token
     * 조합이 azp 일치만으로 인증을 통과할 수 있었습니다(Principal=A, 토큰=B 혼동). 이 메서드는 UserInfo
     * 가용성과 무관하게 Access Token 자체의 서명 검증된 {@code sub} 클레임을 ID Token의 {@code sub}와
     * 직접 비교하여 이 경로를 차단합니다.</p>
     *
     * <p><b>호출 순서:</b> {@link #validateAccessTokenAzp}로 Client 결합(azp)을 검증한 직후 이 메서드로
     * 사용자 결합(sub)을 검증해야 합니다(둘 다 Access Token이 구조적으로 JWT일 때만 호출).</p>
     *
     * <p><b>Opaque Access Token의 한계:</b> Access Token이 Opaque(비-JWT) 형식이면 로컬에서 {@code sub}를
     * 확인할 방법이 없습니다(Keycloak Introspect 응답이 {@code active} 여부만 노출하는 라이브러리 제약).
     * 이 경우 호출부({@code JwtUtil.isStructurallyJwt}로 분기)가 이 메서드를 호출하지 않으며, 기존 정책
     * (UserInfo 200 응답 + {@link #validateSubjectBinding})으로만 보호됩니다 — 회귀 없음. 이 한계를
     * 제거하려면 Keycloak Access Token을 JWT 형식으로 발급하도록 구성해야 합니다.</p>
     *
     * @param accessToken    서명 검증이 완료된 Access Token {@link Jwt} (JWT 형식일 때만 호출)
     * @param idTokenSubject 서명 검증이 완료된 ID Token에서 추출한 subject
     * @throws TokenBindingException Access Token의 subject가 ID Token의 subject와 다를 경우(둘 중
     *     하나라도 null이어서 비교 불가한 경우 포함)
     */
    public static void validateAccessTokenSubject(Jwt accessToken, String idTokenSubject) {
        String accessTokenSubject = accessToken.getSubject();
        if (accessTokenSubject == null || !accessTokenSubject.equals(idTokenSubject)) {
            throw new TokenBindingException(
                "Access Token의 subject(" + accessTokenSubject + ")가 ID Token의 subject("
                    + idTokenSubject + ")와 일치하지 않습니다.");
        }
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
     * <p><b>Medium #2 — UserInfo 부재 시 스킵에 대한 설계상 수용(문서화):</b>
     * {@code require-user-info=false}(기본값)이고 UserInfo 조회에 실패하면 이 sub 결합 검증 자체가
     * 스킵되고, {@code KeycloakPrincipal}은 빈 권한(empty authorities)으로 인증이 성공합니다. 이것이
     * authority confusion(다른 사용자의 권한을 오인하는 것)으로 이어지지 <b>않는</b> 이유는 다음과
     * 같습니다.
     * <ul>
     *   <li><b>권한(authority)의 유일한 원천은 UserInfo입니다.</b> {@code KeycloakAuthorityExtractor}는
     *       UserInfo의 claims에서만 권한을 추출하므로, UserInfo가 없으면 권한도 없습니다(빈 권한) —
     *       "검증되지 않은 잘못된 권한"이 부여될 수 있는 경로 자체가 존재하지 않습니다.</li>
     *   <li><b>신원(identity)은 UserInfo가 아니라 서명 검증을 통과한 ID Token의 sub로 결정됩니다.</b>
     *       {@code KeycloakAuthenticationProvider#createAuthenticatedToken}이 Principal의 subject를
     *       ID Token(JwtDecoder로 서명·iss/exp/nbf 검증 완료)에서 추출하므로, UserInfo 스킵이 "누구인지"
     *       판단에 영향을 주지 않습니다.</li>
     * </ul>
     * 즉 이 스킵 경로는 "권한 없이 신원만 확인된 상태"로 귀결되며, 신원과 권한이 뒤섞여 다른 사용자의
     * 권한이 잘못 부여되는 시나리오(authority confusion)는 이 아키텍처상 발생하지 않습니다. 보안을
     * 강화하려면 {@code keycloak.security.authentication.require-user-info=true}로 설정해 UserInfo
     * 실패를 인증 실패로 승격하세요.</p>
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
