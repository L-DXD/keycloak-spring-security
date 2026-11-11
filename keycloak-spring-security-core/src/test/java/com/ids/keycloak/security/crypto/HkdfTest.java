package com.ids.keycloak.security.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HexFormat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class HkdfTest {

    private static final HexFormat HEX = HexFormat.of();

    @Test
    @DisplayName("RFC 5869 시험 벡터 1과 같다")
    void rfc5869TestCase1() {
        byte[] okm = Hkdf.derive(HEX.parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), HEX.parseHex("000102030405060708090a0b0c"),
            HEX.parseHex("f0f1f2f3f4f5f6f7f8f9"), 42);
        assertThat(HEX.formatHex(okm))
            .isEqualTo("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    }

    @Test
    @DisplayName("RFC 5869 시험 벡터 3(소금·info 없음)과 같다")
    void rfc5869TestCase3() {
        byte[] okm = Hkdf.derive(HEX.parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), new byte[0], new byte[0], 42);
        assertThat(HEX.formatHex(okm))
            .isEqualTo("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
    }

    @Test
    @DisplayName("같은 키라도 용도가 다르면 다른 키가 나온다")
    void purposeSeparatesKeys() {
        byte[] key = new byte[32];
        assertThat(Hkdf.derive(key, "refresh-token", 32)).isNotEqualTo(Hkdf.derive(key, "login-state", 32));
        assertThat(Hkdf.derive(key, "refresh-token", 32)).isEqualTo(Hkdf.derive(key, "refresh-token", 32));
    }
}
