package com.ids.keycloak.security.exception;

/**
 * ID Token과 Access Token(또는 UserInfo)이 동일 사용자·동일 Client에 발급되었는지 검증(토큰 결합 검증)하는
 * 과정에서 실패했을 때 발생하는 예외입니다.
 *
 * <p><b>보안 Advisory 1 대응:</b> 다음 중 하나라도 실패하면 발생합니다.
 * <ul>
 *   <li>ID Token 서명/iss/exp/nbf 검증 실패 ({@code JwtDecoder} 디코딩 실패)</li>
 *   <li>ID Token의 {@code sub}와 UserInfo의 {@code sub}가 불일치</li>
 *   <li>ID Token의 {@code aud}에 client-id가 없음</li>
 *   <li>{@code azp} 클레임이 있는데 client-id와 불일치 (ID Token/Access Token 공통)</li>
 * </ul>
 * 이 예외는 {@link AuthenticationFailedException} 등과 마찬가지로 {@link KeycloakSecurityException}을
 * 상속하는 unchecked 예외이며, Refresh Token 재시도 대상이 아닙니다(재발급으로 해소되지 않는
 * 무결성 위반으로 간주하여 즉시 인증 실패 처리합니다).</p>
 */
public class TokenBindingException extends KeycloakSecurityException {

    public TokenBindingException() {
        super(ErrorCode.TOKEN_BINDING_FAILED);
    }

    public TokenBindingException(String message) {
        super(ErrorCode.TOKEN_BINDING_FAILED, message);
    }

    public TokenBindingException(String message, Throwable cause) {
        super(ErrorCode.TOKEN_BINDING_FAILED, message, cause);
    }
}
