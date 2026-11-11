package com.ids.keycloak.security.sample.e2e;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import tools.jackson.databind.json.JsonMapper;

/**
 * back-channel 로그아웃 E2E(BCL-02~04)용 logout_token. Keycloak이 보내는 토큰은 고를 수 없으므로, 실행마다 새 RSA 키를 만들어
 * 테스트 realm에 우선순위 낮은 서명 키로 넣고(Keycloak은 계속 자기 키로 서명하고, 이 키는 JWKS에만 나온다) 그 키로 직접 서명한다.
 * 앱이 JWKS를 받기 전에 넣어야 하므로 {@link SampleApps}가 앱을 띄우기 전에 부른다.
 */
final class E2eLogoutTokens {

    static final String EVENT = "http://schemas.openid.net/event/backchannel-logout";
    private static final String KEY_NAME = "kss-e2e-logout-token-key";
    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static E2eLogoutTokens instance;

    private final E2eEnvironment env;
    private final PrivateKey realmKey;
    private final String realmKid;
    private final PrivateKey foreignKey;

    private E2eLogoutTokens(E2eEnvironment env) {
        this.env = env;
        KeyPair realm = generate();
        this.realmKey = realm.getPrivate();
        this.realmKid = new KeycloakAdmin(env).replaceRsaKey(KEY_NAME, Base64.getEncoder().encodeToString(realm.getPrivate().getEncoded()), 1);
        this.foreignKey = generate().getPrivate();
    }

    static synchronized E2eLogoutTokens get() {
        if (instance == null) {
            instance = new E2eLogoutTokens(E2eEnvironment.get());
        }
        return instance;
    }

    /** 규격에 맞는 클레임 (iss, aud=clientId, iat, exp, jti, sub, sid, events). 고쳐서 {@link #sign}에 넣는다. */
    Map<String, Object> claims(String clientId, String subject, String sid) {
        Instant now = Instant.now();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", env.issuer());
        claims.put("aud", clientId);
        claims.put("iat", now.getEpochSecond());
        claims.put("exp", now.plusSeconds(120).getEpochSecond());
        claims.put("jti", UUID.randomUUID().toString());
        claims.put("sub", subject);
        if (sid != null) {
            claims.put("sid", sid);
        }
        claims.put("events", Map.of(EVENT, Map.of()));
        return claims;
    }

    /** realm JWKS에 있는 키로 서명한다. */
    String sign(Map<String, Object> claims) {
        return sign(claims, realmKey, realmKid);
    }

    /** realm에 없는 키로 서명한다 (kid도 realm에 없다). */
    String signWithForeignKey(Map<String, Object> claims) {
        return sign(claims, foreignKey, "e2e-unknown-kid");
    }

    private static String sign(Map<String, Object> claims, PrivateKey key, String kid) {
        String header = base64(JSON.writeValueAsBytes(Map.of("alg", "RS256", "typ", "logout+jwt", "kid", kid)));
        String payload = base64(JSON.writeValueAsBytes(claims));
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(key);
            signature.update((header + "." + payload).getBytes(StandardCharsets.US_ASCII));
            return header + "." + payload + "." + base64(signature.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static KeyPair generate() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String base64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
