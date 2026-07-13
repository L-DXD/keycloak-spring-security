package com.ids.keycloak.security.util;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.ids.keycloak.security.exception.TokenBindingException;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * {@link TokenBindingValidator} 단위 테스트.
 *
 * <p>보안 Advisory 1(ID Token ↔ Access Token 사용자·클라이언트 결합 검증) 핵심 로직을 검증합니다.</p>
 */
class TokenBindingValidatorTest {

    private static final String CLIENT_ID = "test-client-id";

    private Jwt buildJwt(String subject, List<String> audience, String azp) {
        Instant now = Instant.now();
        Jwt.Builder builder = Jwt.withTokenValue("token-value")
            .header("alg", "RS256")
            .subject(subject)
            .issuedAt(now)
            .expiresAt(now.plusSeconds(3600));
        if (audience != null) {
            builder.audience(audience);
        }
        if (azp != null) {
            builder.claim("azp", azp);
        }
        return builder.build();
    }

    @Nested
    class validateIdTokenBinding_테스트 {

        @Test
        void aud에_client_id가_포함되고_azp가_없으면_성공한다() {
            Jwt idToken = buildJwt("user-1", List.of(CLIENT_ID), null);

            assertThatCode(() -> TokenBindingValidator.validateIdTokenBinding(idToken, CLIENT_ID))
                .doesNotThrowAnyException();
        }

        @Test
        void aud에_client_id가_포함되고_azp도_client_id와_일치하면_성공한다() {
            Jwt idToken = buildJwt("user-1", List.of(CLIENT_ID), CLIENT_ID);

            assertThatCode(() -> TokenBindingValidator.validateIdTokenBinding(idToken, CLIENT_ID))
                .doesNotThrowAnyException();
        }

        @Test
        void aud에_client_id가_없으면_TokenBindingException이_발생한다() {
            Jwt idToken = buildJwt("user-1", List.of("other-client"), null);

            assertThatThrownBy(() -> TokenBindingValidator.validateIdTokenBinding(idToken, CLIENT_ID))
                .isInstanceOf(TokenBindingException.class)
                .hasMessageContaining("aud");
        }

        @Test
        void azp가_client_id와_다르면_TokenBindingException이_발생한다() {
            Jwt idToken = buildJwt("user-1", List.of(CLIENT_ID), "malicious-client");

            assertThatThrownBy(() -> TokenBindingValidator.validateIdTokenBinding(idToken, CLIENT_ID))
                .isInstanceOf(TokenBindingException.class)
                .hasMessageContaining("azp");
        }

        @Test
        void clientId가_비어있으면_검증을_스킵한다() {
            Jwt idToken = buildJwt("user-1", List.of("other-client"), "other-azp");

            assertThatCode(() -> TokenBindingValidator.validateIdTokenBinding(idToken, ""))
                .doesNotThrowAnyException();
            assertThatCode(() -> TokenBindingValidator.validateIdTokenBinding(idToken, null))
                .doesNotThrowAnyException();
        }
    }

    @Nested
    class validateAccessTokenAzp_테스트 {

        @Test
        void azp가_없으면_aud와_무관하게_성공한다() {
            // Keycloak Access Token은 Audience 매퍼 미설정 시 aud에 client-id가 없는 경우가 흔함
            Jwt accessToken = buildJwt("user-1", List.of("account"), null);

            assertThatCode(() -> TokenBindingValidator.validateAccessTokenAzp(accessToken, CLIENT_ID))
                .doesNotThrowAnyException();
        }

        @Test
        void azp가_client_id와_일치하면_성공한다() {
            Jwt accessToken = buildJwt("user-1", List.of("account"), CLIENT_ID);

            assertThatCode(() -> TokenBindingValidator.validateAccessTokenAzp(accessToken, CLIENT_ID))
                .doesNotThrowAnyException();
        }

        @Test
        void azp가_client_id와_다르면_TokenBindingException이_발생한다() {
            Jwt accessToken = buildJwt("user-1", List.of("account"), "other-client");

            assertThatThrownBy(() -> TokenBindingValidator.validateAccessTokenAzp(accessToken, CLIENT_ID))
                .isInstanceOf(TokenBindingException.class)
                .hasMessageContaining("azp");
        }
    }

    @Nested
    class validateSubjectBinding_테스트 {

        @Test
        void 동일한_subject이면_성공한다() {
            assertThatCode(() -> TokenBindingValidator.validateSubjectBinding("user-1", "user-1"))
                .doesNotThrowAnyException();
        }

        @Test
        void userInfo_subject가_null이면_검증을_스킵한다() {
            // UserInfo 조회 실패(require-user-info=false) 시 회귀 없이 공존
            assertThatCode(() -> TokenBindingValidator.validateSubjectBinding("user-1", null))
                .doesNotThrowAnyException();
        }

        @Test
        void subject가_다르면_TokenBindingException이_발생한다() {
            // A의 ID Token(subject=user-A) + B의 Access Token(UserInfo subject=user-B) 시나리오
            assertThatThrownBy(() -> TokenBindingValidator.validateSubjectBinding("user-A", "user-B"))
                .isInstanceOf(TokenBindingException.class)
                .hasMessageContaining("subject");
        }
    }
}
