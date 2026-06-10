package com.ids.keycloak.security.util;

import com.ids.keycloak.security.config.KeycloakCookieProperties;
import com.ids.keycloak.security.exception.ConfigurationException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.util.StringUtils;

/**
 * Servlet 환경에서 쿠키 생성·추가·삭제를 담당하는 유틸리티 클래스입니다.
 *
 * <p>Jakarta {@link Cookie}는 {@code SameSite} 속성을 지원하지 않으므로,
 * {@link ResponseCookie}로 쿠키를 빌드한 뒤
 * {@link HttpServletResponse#addHeader(String, String)} 방식으로 {@code Set-Cookie} 헤더를 추가합니다.
 * 이를 통해 {@code SameSite}, {@code Secure}, {@code HttpOnly}, {@code Path}, {@code Domain}이
 * 모두 올바르게 직렬화됩니다.</p>
 */
@Slf4j
@UtilityClass
public class CookieUtil {

    public static final String ID_TOKEN_NAME = "id_token";
    public static final String ACCESS_TOKEN_NAME = "access_token";

    private static KeycloakCookieProperties properties;

    /**
     * Cookie 설정을 담당하는 프로퍼티를 주입합니다.
     * AutoConfiguration에서 초기화 시 호출됩니다.
     *
     * @param props 쿠키 설정 프로퍼티
     */
    public static void setProperties(KeycloakCookieProperties props) {
        CookieUtil.properties = props;
    }

    /**
     * 설정된 프로퍼티를 기반으로 {@link ResponseCookie}를 빌드하여
     * {@code Set-Cookie} 헤더 문자열로 반환합니다.
     *
     * <p>{@link ResponseCookie}는 {@code SameSite}를 포함한 모든 쿠키 속성을 RFC 6265 / Same-Site 스펙에
     * 맞게 직렬화하므로, Jakarta {@code Cookie}(SameSite 미지원)의 한계를 극복합니다.</p>
     *
     * @param name   쿠키 이름
     * @param value  쿠키 값 ({@code null}이면 빈 문자열로 처리 — 삭제 전용)
     * @param maxAge 쿠키 만료 시간(초)
     * @return {@code Set-Cookie} 헤더 값 문자열
     */
    private static String buildSetCookieHeader(String name, String value, int maxAge) {
        if (properties == null) {
            throw new ConfigurationException(
                "KeycloakCookieProperties가 초기화되지 않았습니다. AutoConfiguration 설정을 확인하세요.");
        }

        ResponseCookie.ResponseCookieBuilder builder = ResponseCookie
            .from(name, value != null ? value : "")
            .httpOnly(properties.isHttpOnly())
            .secure(properties.isSecure())
            .path(properties.getPath())
            .maxAge(Duration.ofSeconds(maxAge));

        if (StringUtils.hasText(properties.getDomain())) {
            builder.domain(properties.getDomain());
        }

        if (StringUtils.hasText(properties.getSameSite())) {
            builder.sameSite(properties.getSameSite());
        }

        if (log.isTraceEnabled()) {
            log.trace(
                "쿠키 생성: name={}, domain={}, path={}, maxAge={}, secure={}, httpOnly={}, sameSite={}",
                name, properties.getDomain(), properties.getPath(), maxAge,
                properties.isSecure(), properties.isHttpOnly(), properties.getSameSite());
        }

        return builder.build().toString();
    }

    /**
     * 응답에 단일 쿠키를 추가합니다.
     *
     * <p>{@code Set-Cookie} 헤더로 직접 추가하므로 {@code SameSite} 속성이 올바르게 설정됩니다.</p>
     *
     * @param response HttpServletResponse
     * @param name     쿠키 이름
     * @param value    쿠키 값
     * @param maxAge   쿠키 만료 시간(초)
     */
    public static void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
        String setCookieHeader = buildSetCookieHeader(name, value, maxAge);
        response.addHeader(HttpHeaders.SET_COOKIE, setCookieHeader);
    }

    /**
     * Access Token과 ID Token 쿠키를 한 번에 추가합니다.
     *
     * @param response      HttpServletResponse
     * @param accessToken   Access Token 값
     * @param accessMaxAge  Access Token 만료 시간(초)
     * @param idToken       ID Token 값
     * @param idMaxAge      ID Token 만료 시간(초)
     */
    public static void addTokenCookies(
        HttpServletResponse response,
        String accessToken, int accessMaxAge,
        String idToken, int idMaxAge) {

        log.debug("Access Token 및 ID Token 쿠키를 응답에 추가합니다.");
        addCookie(response, ACCESS_TOKEN_NAME, accessToken, accessMaxAge);
        addCookie(response, ID_TOKEN_NAME, idToken, idMaxAge);
    }

    /**
     * 특정 이름의 쿠키를 삭제합니다.
     *
     * @param response HttpServletResponse
     * @param name     삭제할 쿠키 이름
     */
    public static void deleteCookie(HttpServletResponse response, String name) {
        log.debug("쿠키 삭제를 위해 만료시간을 0으로 설정하여 덮어씁니다: [{}]", name);
        addCookie(response, name, null, 0);
    }

    /**
     * 모든 토큰 관련 쿠키를 삭제합니다.
     *
     * @param response HttpServletResponse
     */
    public static void deleteAllTokenCookies(HttpServletResponse response) {
        log.debug("모든 토큰 관련 쿠키(access_token, id_token) 삭제를 요청합니다.");
        deleteCookie(response, ACCESS_TOKEN_NAME);
        deleteCookie(response, ID_TOKEN_NAME);
    }

    /**
     * 요청에서 특정 이름의 쿠키 값을 조회합니다.
     *
     * @param request HttpServletRequest
     * @param name    조회할 쿠키 이름
     * @return 쿠키 값 (Optional)
     */
    public static Optional<String> getCookieValue(HttpServletRequest request, String name) {
        if (request.getCookies() == null) {
            return Optional.empty();
        }
        return Arrays.stream(request.getCookies())
            .filter(cookie -> name.equals(cookie.getName()))
            .map(Cookie::getValue)
            .findFirst();
    }

    /**
     * 만료 시각(Epoch Second)을 기준으로 현재 시점에서의 남은 수명을 계산합니다.
     *
     * @param expireTimeEpochSecond 만료 시각 (Epoch Second)
     * @return 남은 시간 (초)
     */
    public static int calculateRestMaxAge(long expireTimeEpochSecond) {
        long now = Instant.now().getEpochSecond();
        long diff = expireTimeEpochSecond - now;
        return diff > 0 ? (int) diff : 0;
    }

    /**
     * Instant 타입을 기준으로 현재 시점에서의 남은 수명을 계산합니다.
     *
     * @param expiresAt 만료 시각 (Instant)
     * @return 남은 시간 (초), expiresAt이 null인 경우 -1(세션 쿠키) 반환
     */
    public static int calculateRestMaxAge(Instant expiresAt) {
        if (expiresAt == null) return -1;
        return calculateRestMaxAge(expiresAt.getEpochSecond());
    }
}
