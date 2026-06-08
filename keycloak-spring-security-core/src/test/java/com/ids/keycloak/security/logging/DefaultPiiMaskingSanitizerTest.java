package com.ids.keycloak.security.logging;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * {@link DefaultPiiMaskingSanitizer}의 PII 마스킹 패턴을 검증합니다.
 */
class DefaultPiiMaskingSanitizerTest {

    private final DefaultPiiMaskingSanitizer sanitizer = new DefaultPiiMaskingSanitizer();

    private String mask(String value) {
        return sanitizer.sanitize("anyKey", value);
    }

    @Nested
    @DisplayName("PII 패턴 마스킹")
    class Patterns {

        @Test
        @DisplayName("이메일")
        void email() {
            assertThat(mask("alice@example.com")).isEqualTo("a***@example.com");
            assertThat(mask("user=bob@test.co.kr")).isEqualTo("user=b***@test.co.kr");
        }

        @Test
        @DisplayName("휴대폰 (하이픈/무하이픈)")
        void phone() {
            assertThat(mask("010-1234-5678")).isEqualTo("010-****-5678");
            assertThat(mask("01012345678")).isEqualTo("010-****-5678");
        }

        @Test
        @DisplayName("주민번호")
        void rrn() {
            assertThat(mask("900101-1234567")).isEqualTo("900101-1******");
        }

        @Test
        @DisplayName("카드번호 16자리")
        void card() {
            assertThat(mask("1234-5678-9012-3456")).isEqualTo("1234-****-****-3456");
        }

        @Test
        @DisplayName("Bearer 토큰")
        void bearer() {
            assertThat(mask("Bearer eyJhbGciOiJIUzI1Ni9.abc-def_123"))
                .isEqualTo("Bearer ***");
        }
    }

    @Nested
    @DisplayName("경계 케이스")
    class EdgeCases {

        @Test
        @DisplayName("null/빈 문자열은 그대로 반환")
        void nullOrEmpty() {
            assertThat(mask(null)).isNull();
            assertThat(mask("")).isEmpty();
        }

        @Test
        @DisplayName("민감정보가 없으면 원본 유지")
        void noPii() {
            assertThat(mask("name=John&page=1")).isEqualTo("name=John&page=1");
        }

        @Test
        @DisplayName("여러 PII가 섞여 있어도 각각 마스킹")
        void multiple() {
            String input = "email=alice@example.com&phone=010-1234-5678";
            assertThat(mask(input)).isEqualTo("email=a***@example.com&phone=010-****-5678");
        }
    }
}
