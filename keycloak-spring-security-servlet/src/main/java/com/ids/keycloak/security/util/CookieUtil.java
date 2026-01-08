package com.ids.keycloak.security.util;

import com.ids.keycloak.security.config.CookieProperties;
import com.sd.KeycloakClient.dto.auth.KeycloakTokenInfo;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import lombok.experimental.UtilityClass;
import org.springframework.util.StringUtils;

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
            throw new IllegalStateException("CookieProperties has not been initialized. Check AutoConfiguration.");
        }

        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(properties.isHttpOnly());
        cookie.setSecure(properties.isSecure());
        cookie.setPath(properties.getPath());
        cookie.setMaxAge(maxAge);

        if (StringUtils.hasText(properties.getDomain())) {
            cookie.setDomain(properties.getDomain());
        }

        // 서블릿 API(javax.servlet.http.Cookie)는 SameSite 속성을 직접 지원하지 않습니다.
        // Spring Security 또는 Container는 종종 추가 구성 또는 ResponseCookie를 통해 이를 처리합니다.
        // 그러나 기본 Cookie 개체의 경우 필요한 경우 기본 동작이나 사용자 지정 응답 헤더를 사용합니다.
        // Servlet에서 엄격한 SameSite 제어가 필요한 경우 ResponseCookie(Spring Web의)가 선호됩니다.
        // 하지만 여기서는 표준 필터와의 호환성을 위해 HttpServletResponse.addCookie를 고수합니다.
        
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
        addCookie(response, name, null, 0);
    }
    
    /**
     * 모든 토큰 관련 쿠키를 삭제합니다.
     *
     * @param response HttpServletResponse
     */
    public static void deleteAllTokenCookies(HttpServletResponse response) {
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
