package com.ids.keycloak.security.util;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ids.keycloak.security.config.CookieProperties;
import com.ids.keycloak.security.exception.ConfigurationException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class CookieUtilTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Captor
    private ArgumentCaptor<Cookie> cookieCaptor;

    private CookieProperties properties;

    @BeforeEach
    void setUp() {
        properties = new CookieProperties();
        properties.setHttpOnly(true);
        properties.setSecure(true);
        properties.setPath("/app");
        properties.setDomain("example.com");
        CookieUtil.setProperties(properties);
    }

    @Nested
    class 정상_케이스 {

        @Test
        void 프로퍼티_설정에_맞게_쿠키가_생성된다() {
            // When
            CookieUtil.addCookie(response, "test-cookie", "test-value", 3600);

            // Then
            verify(response).addCookie(cookieCaptor.capture());
            Cookie cookie = cookieCaptor.getValue();

            assertThat(cookie.getName()).isEqualTo("test-cookie");
            assertThat(cookie.getValue()).isEqualTo("test-value");
            assertThat(cookie.getMaxAge()).isEqualTo(3600);
            assertThat(cookie.isHttpOnly()).isTrue();
            assertThat(cookie.getSecure()).isTrue();
            assertThat(cookie.getPath()).isEqualTo("/app");
            assertThat(cookie.getDomain()).isEqualTo("example.com");
        }

        @Test
        void 토큰_쿠키_두_개를_한_번에_추가한다() {
            // When
            CookieUtil.addTokenCookies(response, "access-token", 300, "id-token", 3600);

            // Then
            verify(response, times(2)).addCookie(cookieCaptor.capture());
            var cookies = cookieCaptor.getAllValues();

            assertThat(cookies).hasSize(2);
            assertThat(cookies.get(0).getName()).isEqualTo(CookieUtil.ACCESS_TOKEN_NAME);
            assertThat(cookies.get(0).getValue()).isEqualTo("access-token");
            assertThat(cookies.get(1).getName()).isEqualTo(CookieUtil.ID_TOKEN_NAME);
            assertThat(cookies.get(1).getValue()).isEqualTo("id-token");
        }

        @Test
        void 요청에서_쿠키_값을_조회한다() {
            // Given
            Cookie[] cookies = {
                new Cookie("other", "other-value"),
                new Cookie("target", "target-value")
            };
            when(request.getCookies()).thenReturn(cookies);

            // When
            Optional<String> result = CookieUtil.getCookieValue(request, "target");

            // Then
            assertThat(result).isPresent().contains("target-value");
        }

        @Test
        void 쿠키_삭제_시_MaxAge가_0인_쿠키를_덮어쓴다() {
            // When
            CookieUtil.deleteCookie(response, "to-delete");

            // Then
            verify(response).addCookie(cookieCaptor.capture());
            Cookie cookie = cookieCaptor.getValue();

            assertThat(cookie.getName()).isEqualTo("to-delete");
            assertThat(cookie.getValue()).isNull();
            assertThat(cookie.getMaxAge()).isZero();
        }

        @Test
        void 모든_토큰_쿠키를_삭제한다() {
            // When
            CookieUtil.deleteAllTokenCookies(response);

            // Then
            verify(response, times(2)).addCookie(argThat(cookie -> cookie.getMaxAge() == 0));
        }

        @Test
        void EpochSecond로_남은_만료_시간을_계산한다() {
            // Given
            long futureTime = Instant.now().getEpochSecond() + 100;

            // When
            int result = CookieUtil.calculateRestMaxAge(futureTime);

            // Then - 오차 범위 허용 (1초)
            assertThat(result).isBetween(99, 101);
        }

        @Test
        void Instant로_남은_만료_시간을_계산한다() {
            // Given
            Instant futureTime = Instant.now().plusSeconds(100);

            // When
            int result = CookieUtil.calculateRestMaxAge(futureTime);

            // Then
            assertThat(result).isBetween(99, 101);
        }
    }

    @Nested
    class 바운더리_케이스 {

        @Test
        void 쿠키가_없으면_빈_Optional을_반환한다() {
            // Given
            Cookie[] cookies = { new Cookie("other", "value") };
            when(request.getCookies()).thenReturn(cookies);

            // When
            Optional<String> result = CookieUtil.getCookieValue(request, "not-exists");

            // Then
            assertThat(result).isEmpty();
        }

        @Test
        void request_getCookies가_null이면_빈_Optional을_반환한다() {
            // Given
            when(request.getCookies()).thenReturn(null);

            // When
            Optional<String> result = CookieUtil.getCookieValue(request, "any");

            // Then
            assertThat(result).isEmpty();
        }

        @Test
        void 만료_시간이_이미_지났으면_0을_반환한다() {
            // Given
            long pastTime = Instant.now().getEpochSecond() - 100;

            // When
            int result = CookieUtil.calculateRestMaxAge(pastTime);

            // Then
            assertThat(result).isZero();
        }

        @Test
        void Instant가_null이면_마이너스1을_반환한다() {
            // When
            int result = CookieUtil.calculateRestMaxAge((Instant) null);

            // Then
            assertThat(result).isEqualTo(-1);
        }

        @Test
        void domain이_비어있으면_쿠키에_domain을_설정하지_않는다() {
            // Given
            properties.setDomain("");
            CookieUtil.setProperties(properties);

            // When
            CookieUtil.addCookie(response, "test", "value", 100);

            // Then
            verify(response).addCookie(cookieCaptor.capture());
            Cookie cookie = cookieCaptor.getValue();
            assertThat(cookie.getDomain()).isNull();
        }
    }

    @Nested
    class 실패_케이스 {

        @Test
        void CookieProperties가_초기화되지_않으면_ConfigurationException이_발생한다() {
            // Given
            CookieUtil.setProperties(null);

            // When & Then
            assertThatThrownBy(() -> CookieUtil.addCookie(response, "test", "value", 100))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining("CookieProperties가 초기화되지 않았습니다");
        }
    }
}
