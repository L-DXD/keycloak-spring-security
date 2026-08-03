package com.ids.keycloak.security.authentication;

/**
 * {@link KeycloakLoginService#authenticate(jakarta.servlet.http.HttpServletRequest,
 * jakarta.servlet.http.HttpServletResponse, KeycloakTokens)}에 전달하는 토큰 묶음입니다.
 *
 * <p>Token Exchange, 커스텀 SSO 핸드오프 등 OIDC 리다이렉트 흐름 밖에서 이미 발급받은 ID/Access/
 * Refresh Token을 하나의 값 객체로 전달하기 위한 용도입니다. Refresh Token은 선택 항목이며,
 * {@code null}이면 세션에 저장하지 않습니다(이후 재발급이 필요한 흐름에서는 재로그인이 필요합니다).</p>
 *
 * @param idToken      ID Token (필수) — {@link KeycloakAuthenticationProvider#createAuthenticatedToken}로
 *                      서명·클레임 검증됩니다.
 * @param accessToken  Access Token (필수) — UserInfo 조회 및 토큰 결합 검증에 사용됩니다.
 * @param refreshToken Refresh Token (선택, {@code null} 가능) — 세션에 저장되어 이후 토큰 재발급에 사용됩니다.
 */
public record KeycloakTokens(String idToken, String accessToken, String refreshToken) {

    public KeycloakTokens {
        if (idToken == null || idToken.isBlank()) {
            throw new IllegalArgumentException("idToken은 필수입니다.");
        }
        if (accessToken == null || accessToken.isBlank()) {
            throw new IllegalArgumentException("accessToken은 필수입니다.");
        }
    }

    /**
     * Refresh Token 없이 토큰 묶음을 생성합니다.
     */
    public static KeycloakTokens of(String idToken, String accessToken) {
        return new KeycloakTokens(idToken, accessToken, null);
    }

    /**
     * Refresh Token을 포함한 토큰 묶음을 생성합니다.
     */
    public static KeycloakTokens of(String idToken, String accessToken, String refreshToken) {
        return new KeycloakTokens(idToken, accessToken, refreshToken);
    }
}
