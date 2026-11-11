package com.ids.keycloak.security.crypto;

import java.util.Arrays;
import java.util.Objects;

/**
 * 암호화한 토큰과 그때 쓴 키 id. 세션 행의 {@code refresh_token_enc}, {@code enc_key_id}.
 *
 * @param keyId      키 묶음의 키 id
 * @param ciphertext nonce(12바이트) + 암호문 + 태그(16바이트)
 */
public record EncryptedToken(String keyId, byte[] ciphertext) {

    public EncryptedToken {
        Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(ciphertext, "ciphertext");
        ciphertext = ciphertext.clone();
    }

    @Override
    public byte[] ciphertext() {
        return ciphertext.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof EncryptedToken e && keyId.equals(e.keyId) && Arrays.equals(ciphertext, e.ciphertext);
    }

    @Override
    public int hashCode() {
        return 31 * keyId.hashCode() + Arrays.hashCode(ciphertext);
    }

    @Override
    public String toString() {
        return "EncryptedToken[keyId=" + keyId + ", " + ciphertext.length + " bytes]";
    }
}
