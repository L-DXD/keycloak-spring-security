package com.ids.keycloak.security.crypto;

/**
 * 암호문을 풀지 못했다 (모르는 키 id, 위조, 손상). 메시지에 암호문·키 값을 넣지 않는다.
 */
public class TokenDecryptionException extends RuntimeException {

    public TokenDecryptionException(String message) {
        super(message);
    }

    public TokenDecryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
