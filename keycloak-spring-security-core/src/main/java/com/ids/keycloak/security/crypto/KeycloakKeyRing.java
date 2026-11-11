package com.ids.keycloak.security.crypto;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * 키 묶음 ({@code keycloak.security.crypto.*}). 키 id마다 32바이트 이상의 키가 있고, 새로 암호화할 때는 활성 키를 쓴다.
 * <p>
 * 리프레시 토큰 암호화, 로그인 임시 쿠키, CSRF 서명에 쓰는 용도별 키는 이 묶음에서 HKDF로 나눠 만든다 (#116).
 * {@link #toString()}에는 키 값이 나오지 않는다.
 */
public class KeycloakKeyRing {

    /** 키 하나의 최소 길이(바이트). */
    public static final int MIN_KEY_BYTES = 32;

    private final String activeKeyId;
    private final Map<String, byte[]> keys;

    /**
     * @param activeKeyId 새로 암호화할 때 쓰는 키 id. {@code keys}에 있어야 한다
     * @param keys        키 id → 키 (32바이트 이상)
     */
    public KeycloakKeyRing(String activeKeyId, Map<String, byte[]> keys) {
        if (keys == null || keys.isEmpty()) {
            throw new IllegalArgumentException("키가 하나도 없다");
        }
        if (!keys.containsKey(activeKeyId)) {
            throw new IllegalArgumentException("활성 키 id가 키 묶음에 없다: " + activeKeyId);
        }
        Map<String, byte[]> copy = new LinkedHashMap<>();
        keys.forEach((id, key) -> {
            if (key == null || key.length < MIN_KEY_BYTES) {
                throw new IllegalArgumentException("키 " + id + "가 " + MIN_KEY_BYTES + "바이트보다 짧다");
            }
            copy.put(id, key.clone());
        });
        this.activeKeyId = activeKeyId;
        this.keys = Collections.unmodifiableMap(copy);
    }

    public String activeKeyId() {
        return activeKeyId;
    }

    /** 활성 키. 돌려받은 배열을 바꿔도 묶음은 바뀌지 않는다. */
    public byte[] activeKey() {
        return key(activeKeyId);
    }

    public Set<String> keyIds() {
        return keys.keySet();
    }

    public boolean contains(String keyId) {
        return keys.containsKey(keyId);
    }

    /**
     * @throws IllegalArgumentException 모르는 키 id
     */
    public byte[] key(String keyId) {
        byte[] key = keys.get(keyId);
        if (key == null) {
            throw new IllegalArgumentException("모르는 키 id: " + keyId);
        }
        return key.clone();
    }

    @Override
    public String toString() {
        return "KeycloakKeyRing[active=" + activeKeyId + ", ids=" + keys.keySet() + "]";
    }
}
