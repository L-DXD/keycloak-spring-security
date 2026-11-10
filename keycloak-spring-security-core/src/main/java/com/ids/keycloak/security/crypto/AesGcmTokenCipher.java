package com.ids.keycloak.security.crypto;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 기본 토큰 암호: AES-256-GCM. 키 묶음의 키마다 용도별 키를 HKDF로 만든다 (용도 = {@code purpose}).
 * <p>
 * 암호문 = nonce(12바이트, 난수) + 암호문 + 태그(16바이트). 키 id와 용도를 AAD로 묶어, 다른 키 id·다른 용도로 옮긴 암호문은 풀리지 않는다.
 */
public class AesGcmTokenCipher implements TokenCipher {

    /** 리프레시 토큰 용도. */
    public static final String REFRESH_TOKEN_PURPOSE = "refresh-token";

    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;

    private final KeycloakKeyRing keyRing;
    private final String purpose;
    private final Map<String, SecretKeySpec> keys = new LinkedHashMap<>();
    private final SecureRandom random = new SecureRandom();

    public AesGcmTokenCipher(KeycloakKeyRing keyRing) {
        this(keyRing, REFRESH_TOKEN_PURPOSE);
    }

    public AesGcmTokenCipher(KeycloakKeyRing keyRing, String purpose) {
        this.keyRing = Objects.requireNonNull(keyRing);
        this.purpose = Objects.requireNonNull(purpose);
        for (String id : keyRing.keyIds()) {
            keys.put(id, new SecretKeySpec(Hkdf.derive(keyRing.key(id), purpose, 32), "AES"));
        }
    }

    @Override
    public EncryptedToken encrypt(String plaintext) {
        Objects.requireNonNull(plaintext, "plaintext");
        String keyId = keyRing.activeKeyId();
        try {
            byte[] nonce = new byte[NONCE_BYTES];
            random.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keys.get(keyId), new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(aad(keyId));
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return new EncryptedToken(keyId, ByteBuffer.allocate(NONCE_BYTES + encrypted.length).put(nonce).put(encrypted).array());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("암호화하지 못했다", e);
        }
    }

    @Override
    public String decrypt(EncryptedToken token) {
        SecretKeySpec key = keys.get(token.keyId());
        if (key == null) {
            throw new TokenDecryptionException("모르는 키 id입니다: " + token.keyId());
        }
        byte[] data = token.ciphertext();
        if (data.length < NONCE_BYTES + TAG_BITS / 8) {
            throw new TokenDecryptionException("암호문이 너무 짧습니다");
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, data, 0, NONCE_BYTES));
            cipher.updateAAD(aad(token.keyId()));
            byte[] plain = cipher.doFinal(data, NONCE_BYTES, data.length - NONCE_BYTES);
            return new String(plain, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new TokenDecryptionException("암호문을 풀지 못했습니다 (위조·손상 또는 다른 키)", e);
        }
    }

    @Override
    public boolean needsReEncryption(EncryptedToken token) {
        return !keyRing.activeKeyId().equals(token.keyId());
    }

    private byte[] aad(String keyId) {
        return ("kss:" + purpose + ":" + keyId).getBytes(StandardCharsets.US_ASCII);
    }
}
