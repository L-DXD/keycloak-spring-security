package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;

/**
 * {@link CsrfTokenRepositoryFactory}가 {@link CsrfTokenRepositoryMode}별로 기대한 저장소를
 * 생성하는지 검증한다 (f5d82de, 항목 4).
 *
 * <p>기본값({@code SESSION})은 {@code null}을 반환해 호출부가 Spring Security 기본 CSRF 토큰
 * 저장소({@code HttpSessionCsrfTokenRepository})를 그대로 쓰도록 강제한다(회귀 0).</p>
 */
class CsrfTokenRepositoryFactoryTest {

    @Nested
    class SESSION_모드 {

        @Test
        void SESSION_모드는_null을_반환해_Spring_Security_기본_동작을_유지한다() {
            CsrfTokenRepository repository = CsrfTokenRepositoryFactory.create(CsrfTokenRepositoryMode.SESSION);

            assertThat(repository).isNull();
        }

        @Test
        void mode가_null이면_기본값인_SESSION으로_처리되어_null을_반환한다() {
            CsrfTokenRepository repository = CsrfTokenRepositoryFactory.create(null);

            assertThat(repository).isNull();
        }
    }

    @Nested
    class COOKIE_모드 {

        @Test
        void COOKIE_모드는_CookieCsrfTokenRepository를_반환한다() {
            CsrfTokenRepository repository = CsrfTokenRepositoryFactory.create(CsrfTokenRepositoryMode.COOKIE);

            assertThat(repository).isInstanceOf(CookieCsrfTokenRepository.class);
        }

        @Test
        void COOKIE_모드가_생성한_저장소는_httpOnly가_false인_쿠키를_발급한다() {
            // CookieCsrfTokenRepository.withHttpOnlyFalse()로 생성되었는지는 필드가 노출되지 않으므로,
            // 실제 saveToken() 동작(response.addCookie)을 통해 httpOnly=false를 검증한다 — 프로덕션
            // 생성 로직을 복제하지 않고 실제 산출물을 경유해 확인한다.
            CsrfTokenRepository repository = CsrfTokenRepositoryFactory.create(CsrfTokenRepositoryMode.COOKIE);

            HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
            HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
            Mockito.when(request.getContextPath()).thenReturn("");
            CsrfToken token = repository.generateToken(request);

            repository.saveToken(token, request, response);

            ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);
            Mockito.verify(response).addCookie(cookieCaptor.capture());
            assertThat(cookieCaptor.getValue().isHttpOnly()).isFalse();
        }
    }

    @Nested
    class 호출마다_새_인스턴스 {

        @Test
        void COOKIE_모드는_호출마다_새로운_인스턴스를_생성한다() {
            CsrfTokenRepository first = CsrfTokenRepositoryFactory.create(CsrfTokenRepositoryMode.COOKIE);
            CsrfTokenRepository second = CsrfTokenRepositoryFactory.create(CsrfTokenRepositoryMode.COOKIE);

            assertThat(first).isNotSameAs(second);
        }
    }
}
