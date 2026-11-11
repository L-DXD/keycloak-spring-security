package com.ids.keycloak.security.session;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * sid 쿠키 값 만들기와 해시. sid는 256비트 난수라 소금 없는 SHA-256으로 충분하다.
 */
public final class SessionIds {

    private static final SecureRandom RANDOM = new SecureRandom();

    private SessionIds() {
    }

    /** 새 sid 쿠키 값 (32바이트 난수, base64url, 43자). */
    public static String newSid() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** 세션 행 {@code sid_hash} 값 (SHA-256 hex, 64자). */
    public static String hash(String sid) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(sid.getBytes(StandardCharsets.US_ASCII));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** 쿠키 값이 sid 모양인가 (길이·문자). 아니면 DB를 보지 않고 버린다. */
    public static boolean looksLikeSid(String value) {
        return value != null && value.length() == 43 && value.chars().allMatch(c ->
            (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_');
    }
}
