package com.ids.keycloak.security.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AesGcmTokenCipherTest {

    private static final String REFRESH_TOKEN = "eyJhbGciOiJIUzI1NiJ9.refresh-token-body.signature";

    static byte[] key(int seed) {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) seed);
        return key;
    }

    static KeycloakKeyRing ring(String active, String... ids) {
        Map<String, byte[]> keys = new LinkedHashMap<>();
        for (int i = 0; i < ids.length; i++) {
            keys.put(ids[i], key(i + 1));
        }
        return new KeycloakKeyRing(active, keys);
    }

    @Test
    @DisplayName("암호화하고 다시 풀면 같은 값이고, 암호문에 원문이 없다")
    void roundTrip() {
        AesGcmTokenCipher cipher = new AesGcmTokenCipher(ring("k1", "k1"));
        EncryptedToken token = cipher.encrypt(REFRESH_TOKEN);

        assertThat(token.keyId()).isEqualTo("k1");
        assertThat(new String(token.ciphertext(), StandardCharsets.ISO_8859_1)).doesNotContain("refresh-token-body");
        assertThat(cipher.decrypt(token)).isEqualTo(REFRESH_TOKEN);
    }

    @Test
    @DisplayName("같은 값을 두 번 암호화해도 암호문이 다르다 (nonce 난수)")
    void nonceIsRandom() {
        AesGcmTokenCipher cipher = new AesGcmTokenCipher(ring("k1", "k1"));
        assertThat(cipher.encrypt(REFRESH_TOKEN)).isNotEqualTo(cipher.encrypt(REFRESH_TOKEN));
    }

    @Test
    @DisplayName("STORE-02 k1로 암호화한 행은 활성 키를 k2로 바꿔도 k1로 풀리고, 다음 갱신 때 k2로 다시 저장된다")
    void keyRotation() {
        EncryptedToken old = new AesGcmTokenCipher(ring("k1", "k1")).encrypt(REFRESH_TOKEN);

        AesGcmTokenCipher rotated = new AesGcmTokenCipher(ring("k2", "k1", "k2"));
        assertThat(rotated.decrypt(old)).isEqualTo(REFRESH_TOKEN);
        assertThat(rotated.needsReEncryption(old)).isTrue();

        EncryptedToken renewed = rotated.encrypt(REFRESH_TOKEN);
        assertThat(renewed.keyId()).isEqualTo("k2");
        assertThat(rotated.needsReEncryption(renewed)).isFalse();
        assertThat(rotated.decrypt(renewed)).isEqualTo(REFRESH_TOKEN);
    }

    @Test
    @DisplayName("STORE-03 암호문을 1바이트 바꾸면 TokenDecryptionException (부른 쪽이 로컬 로그아웃으로 처리)")
    void tamperedCiphertext() {
        AesGcmTokenCipher cipher = new AesGcmTokenCipher(ring("k1", "k1"));
        byte[] bytes = cipher.encrypt(REFRESH_TOKEN).ciphertext();
        for (int position : new int[] {0, 12, bytes.length / 2, bytes.length - 1}) {
            byte[] tampered = bytes.clone();
            tampered[position] ^= 0x01;
            assertThatThrownBy(() -> cipher.decrypt(new EncryptedToken("k1", tampered)))
                .isInstanceOf(TokenDecryptionException.class)
                .hasMessageNotContaining(REFRESH_TOKEN);
        }
    }

    @Test
    @DisplayName("STORE-03 짧은 암호문, 모르는 키 id도 TokenDecryptionException")
    void malformed() {
        AesGcmTokenCipher cipher = new AesGcmTokenCipher(ring("k1", "k1"));
        assertThatThrownBy(() -> cipher.decrypt(new EncryptedToken("k1", new byte[5]))).isInstanceOf(TokenDecryptionException.class);
        EncryptedToken token = cipher.encrypt(REFRESH_TOKEN);
        assertThatThrownBy(() -> cipher.decrypt(new EncryptedToken("k9", token.ciphertext())))
            .isInstanceOf(TokenDecryptionException.class)
            .hasMessageContaining("k9");
    }

    @Test
    @DisplayName("키 id를 바꿔 붙이거나 다른 용도의 암호문을 옮기면 풀리지 않는다 (AAD)")
    void aadBindsKeyIdAndPurpose() {
        KeycloakKeyRing sameKeys = new KeycloakKeyRing("k1", Map.of("k1", key(7), "k2", key(7)));
        AesGcmTokenCipher cipher = new AesGcmTokenCipher(sameKeys);
        EncryptedToken token = cipher.encrypt(REFRESH_TOKEN);
        assertThatThrownBy(() -> cipher.decrypt(new EncryptedToken("k2", token.ciphertext())))
            .isInstanceOf(TokenDecryptionException.class);

        AesGcmTokenCipher otherPurpose = new AesGcmTokenCipher(sameKeys, "login-state");
        assertThatThrownBy(() -> otherPurpose.decrypt(token)).isInstanceOf(TokenDecryptionException.class);
    }

    @Test
    @DisplayName("EncryptedToken toString에 암호문이 나오지 않는다")
    void toStringRedacted() {
        EncryptedToken token = new AesGcmTokenCipher(ring("k1", "k1")).encrypt(REFRESH_TOKEN);
        assertThat(token.toString()).isEqualTo("EncryptedToken[keyId=k1, " + token.ciphertext().length + " bytes]");
    }
}
