package com.ids.keycloak.security.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HKDF-SHA256 (RFC 5869). 키 묶음의 키 하나에서 용도별 키를 나눠 만든다 (01 설계 5-2).
 */
public final class Hkdf {

    private static final String HMAC = "HmacSHA256";
    private static final int HASH_LEN = 32;
    private static final byte[] SALT = "keycloak-spring-security/v3".getBytes(StandardCharsets.US_ASCII);

    private Hkdf() {
    }

    /**
     * @param inputKey 키 묶음의 키 (32바이트 이상)
     * @param purpose  용도. 예: {@code refresh-token}
     * @param length   만들 키 길이(바이트, 255*32 이하)
     */
    public static byte[] derive(byte[] inputKey, String purpose, int length) {
        return derive(inputKey, SALT, ("kss:" + purpose).getBytes(StandardCharsets.US_ASCII), length);
    }

    /** RFC 5869 그대로 (시험 벡터 확인용). */
    static byte[] derive(byte[] inputKey, byte[] salt, byte[] info, int length) {
        if (length <= 0 || length > 255 * HASH_LEN) {
            throw new IllegalArgumentException("length는 1~" + (255 * HASH_LEN) + "이어야 한다");
        }
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(salt.length == 0 ? new byte[HASH_LEN] : salt, HMAC));
            byte[] prk = mac.doFinal(inputKey);

            mac.init(new SecretKeySpec(prk, HMAC));
            byte[] out = new byte[length];
            byte[] block = new byte[0];
            int offset = 0;
            for (int i = 1; offset < length; i++) {
                mac.update(block);
                mac.update(info);
                mac.update((byte) i);
                block = mac.doFinal();
                int n = Math.min(HASH_LEN, length - offset);
                System.arraycopy(block, 0, out, offset, n);
                offset += n;
            }
            Arrays.fill(prk, (byte) 0);
            return out;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HKDF를 만들 수 없다", e);
        }
    }
}
