package com.ids.keycloak.security.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * CSRF 토큰 만들기·확인 (01 설계 5-2). 토큰 = {@code 키id.난수.서명}, 서명 = HMAC-SHA256(용도별 키, sid + 난수).
 * <p>
 * sid에 묶여 있어 다른 사람의 토큰은 통하지 않고(CSRF-04), 로그인하면 sid가 바뀌어 예전 토큰이 통하지 않는다(CSRF-06).
 */
public class KeycloakCsrfTokenSigner {

    /** HKDF 용도. */
    public static final String PURPOSE = "csrf";

    private static final int RANDOM_BYTES = 16;
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private final KeycloakKeyRing keyRing;
    private final Map<String, byte[]> keys = new LinkedHashMap<>();
    private final SecureRandom random = new SecureRandom();

    public KeycloakCsrfTokenSigner(KeycloakKeyRing keyRing) {
        this.keyRing = Objects.requireNonNull(keyRing);
        for (String id : keyRing.keyIds()) {
            keys.put(id, Hkdf.derive(keyRing.key(id), PURPOSE, 32));
        }
    }

    /** sid에 묶인 새 토큰. */
    public String create(String sid) {
        Objects.requireNonNull(sid, "sid");
        byte[] nonce = new byte[RANDOM_BYTES];
        random.nextBytes(nonce);
        String keyId = keyRing.activeKeyId();
        return keyId + "." + ENCODER.encodeToString(nonce) + "." + ENCODER.encodeToString(mac(keys.get(keyId), sid, nonce));
    }

    /** 토큰이 이 sid로 만든 것인가. 모양이 틀리거나 모르는 키 id면 {@code false}. */
    public boolean matches(String sid, String token) {
        if (sid == null || token == null || token.length() > 256) {
            return false;
        }
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            return false;
        }
        byte[] key = keys.get(parts[0]);
        if (key == null) {
            return false;
        }
        try {
            byte[] nonce = DECODER.decode(parts[1]);
            byte[] signature = DECODER.decode(parts[2]);
            return nonce.length == RANDOM_BYTES && MessageDigest.isEqual(mac(key, sid, nonce), signature);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static byte[] mac(byte[] key, String sid, byte[] nonce) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            mac.update(sid.getBytes(StandardCharsets.US_ASCII));
            mac.update((byte) 0);
            return mac.doFinal(nonce);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC을 만들 수 없다", e);
        }
    }
}
