package com.ids.keycloak.security.util;

import com.ids.keycloak.security.config.CookieProperties;
import com.ids.keycloak.security.exception.ConfigurationException;
import com.sd.KeycloakClient.dto.auth.KeycloakTokenInfo;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

@Slf4j
@UtilityClass
public class CookieUtil {

    public static final String ID_TOKEN_NAME = "id_token";
    public static final String ACCESS_TOKEN_NAME = "access_token";

    private static CookieProperties properties;

    /**
     * Cookie 설정을 담당하는 프로퍼티를 주입합니다.
     * AutoConfiguration에서 초기화 시 호출됩니다.
     *
     * @param props 쿠키 설정 프로퍼티
     */
    public static void setProperties(CookieProperties props) {
        CookieUtil.properties = props;
    }

    /**
     * 설정된 프로퍼티를 기반으로 새로운 Cookie 객체를 생성합니다.
     *
     * @param name   쿠키 이름
     * @param value  쿠키 값
     * @param maxAge 쿠키 만료 시간(초)
     * @return 생성된 Cookie 객체
     */
    private static Cookie createCookie(String name, String value, int maxAge) {
        if (properties == null) {
            throw new ConfigurationException("CookieProperties가 초기화되지 않았습니다. AutoConfiguration 설정을 확인하세요.");
        }

        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(properties.isHttpOnly());
        cookie.setSecure(properties.isSecure());
        cookie.setPath(properties.getPath());
        cookie.setMaxAge(maxAge);

        if (StringUtils.hasText(properties.getDomain())) {
            cookie.setDomain(properties.getDomain());
        }

        if (log.isTraceEnabled()) {
            log.trace("쿠키 생성: name={}, domain={}, path={}, maxAge={}, secure={}, httpOnly={}", name, cookie.getDomain(), cookie.getPath(), maxAge, cookie.getSecure(), cookie.isHttpOnly());
        }
        
        return cookie;
    }

    /**
     * 응답에 단일 쿠키를 추가합니다.
     *
     * @param response HttpServletResponse
     * @param name     쿠키 이름
     * @param value    쿠키 값
     * @param maxAge   쿠키 만료 시간(초)
     */
    public static void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
        response.addCookie(createCookie(name, value, maxAge));
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
    public static void addTokenCookies(HttpServletResponse response, String accessToken, int accessMaxAge, String idToken, int idMaxAge) {
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
