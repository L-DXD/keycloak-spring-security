package com.ids.keycloak.security.config;

import lombok.experimental.UtilityClass;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;

/**
 * {@link CsrfTokenRepositoryMode} 설정값에 해당하는 {@link CsrfTokenRepository} 인스턴스를 생성하는
 * 유틸리티입니다.
 *
 * <p>{@link CsrfTokenRepositoryMode#SESSION}(기본값)은 Spring Security의 기존 기본 동작(
 * {@code HttpSessionCsrfTokenRepository})과 동일하므로 {@code null}을 반환한다. 호출부는
 * {@code null}이면 {@code csrf.csrfTokenRepository(...)}를 아예 호출하지 않아 Spring Security의
 * 기본값을 그대로 유지해야 한다(회귀 0 보장, 명시적 재구성 자체를 생략).</p>
 *
 * @see CsrfTokenRepositoryMode
 */
@UtilityClass
public class CsrfTokenRepositoryFactory {

    /**
     * 지정된 정책에 해당하는 {@link CsrfTokenRepository}를 생성합니다.
     *
     * @param mode 저장 정책 ({@code null}이면 {@link CsrfTokenRepositoryMode#SESSION}로 처리)
     * @return {@link CsrfTokenRepositoryMode#COOKIE}면 {@code CookieCsrfTokenRepository.withHttpOnlyFalse()},
     *     {@link CsrfTokenRepositoryMode#SESSION}(기본값)이면 {@code null}(Spring Security 기본값 유지)
     */
    public static CsrfTokenRepository create(CsrfTokenRepositoryMode mode) {
        CsrfTokenRepositoryMode effectiveMode = mode != null ? mode : CsrfTokenRepositoryMode.SESSION;
        if (effectiveMode == CsrfTokenRepositoryMode.COOKIE) {
            return CookieCsrfTokenRepository.withHttpOnlyFalse();
        }
        return null;
    }
}
