package com.ids.keycloak.security.web.cookie;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 기본 쿠키: {@code __Host-{앱 이름}_{sid|at|csrf|login}}, Secure, HttpOnly, SameSite=Lax, Path=/, Domain 없음.
 * <p>
 * {@code __Host-} 접두사는 브라우저가 Secure·Path=/·Domain 없음을 강제하게 해서, 하위 도메인이 쿠키를 덮어쓰지 못한다.
 * 속성을 바꾸려면 {@link #cookie(KeycloakCookie, String)}를 덮어쓴다.
 */
public class DefaultKeycloakCookieWriter implements KeycloakCookieWriter {

    private static final Logger log = LoggerFactory.getLogger(DefaultKeycloakCookieWriter.class);

    /** 쿠키 이름 접두사. */
    public static final String HOST_PREFIX = "__Host-";
    /** 브라우저가 받는 쿠키 하나의 크기 상한(이름 + 값). 넘으면 브라우저가 버린다. */
    public static final int MAX_COOKIE_BYTES = 4096;

    private static final Pattern APP_NAME = Pattern.compile("[A-Za-z0-9-]{1,32}");

    private final Map<KeycloakCookie, String> names = new EnumMap<>(KeycloakCookie.class);
    private final Set<KeycloakCookie> sizeWarned = ConcurrentHashMap.newKeySet();

    /**
     * @param appName 앱 이름 (영문·숫자·-, 32자까지). 쿠키 이름에 들어간다 (COOKIE-05)
     */
    public DefaultKeycloakCookieWriter(String appName) {
        if (appName == null || !APP_NAME.matcher(appName).matches()) {
            throw new IllegalArgumentException("앱 이름은 영문·숫자·-만 32자까지 됩니다: " + appName);
        }
        for (KeycloakCookie cookie : KeycloakCookie.values()) {
            names.put(cookie, HOST_PREFIX + appName + "_" + cookie.suffix());
        }
    }

    @Override
    public String name(KeycloakCookie cookie) {
        return names.get(cookie);
    }

    @Override
    public Optional<String> read(HttpServletRequest request, KeycloakCookie cookie) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return Optional.empty();
        }
        String name = name(cookie);
        for (Cookie c : cookies) {
            if (name.equals(c.getName())) {
                String value = c.getValue();
                return value == null || value.isEmpty() ? Optional.empty() : Optional.of(value);
            }
        }
        return Optional.empty();
    }

    @Override
    public void write(HttpServletResponse response, KeycloakCookie cookie, String value, Duration maxAge) {
        Objects.requireNonNull(value, "value");
        long seconds = maxAge == null ? 0 : maxAge.toSeconds();
        if (seconds <= 0) {
            clear(response, cookie);
            return;
        }
        warnIfTooLarge(cookie, value);
        add(response, cookie(cookie, value).maxAge(seconds).build());
    }

    @Override
    public void clear(HttpServletResponse response, KeycloakCookie cookie) {
        add(response, cookie(cookie, "").maxAge(0).build());
    }

    /**
     * 쿠키 속성. 이름과 값만 정해진 상태로 Secure, HttpOnly, SameSite=Lax, Path=/를 붙인다. Domain은 넣지 않는다.
     * 쓰기와 지우기가 이 메서드를 같이 써서 속성이 늘 같다.
     */
    protected ResponseCookie.ResponseCookieBuilder cookie(KeycloakCookie cookie, String value) {
        return ResponseCookie.from(name(cookie), value)
            .secure(true)
            .httpOnly(true)
            .sameSite("Lax")
            .path("/");
    }

    private static void add(HttpServletResponse response, ResponseCookie cookie) {
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    private void warnIfTooLarge(KeycloakCookie cookie, String value) {
        int size = name(cookie).length() + value.getBytes(StandardCharsets.US_ASCII).length;
        if (size > MAX_COOKIE_BYTES - 96 && sizeWarned.add(cookie)) {
            log.warn("[KSS] {} 쿠키가 {}바이트입니다. 브라우저는 {}바이트가 넘는 쿠키를 버립니다. "
                    + "Keycloak client의 scope·mapper를 줄여 토큰을 작게 하세요 (같은 경고는 한 번만 찍습니다)",
                name(cookie), size, MAX_COOKIE_BYTES);
        }
    }
}
