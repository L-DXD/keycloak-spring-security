package com.ids.keycloak.security.web.cookie;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.http.Cookie;

class DefaultKeycloakCookieWriterTest {

    private final DefaultKeycloakCookieWriter writer = new DefaultKeycloakCookieWriter("demo");

    @Test
    @DisplayName("쿠키 이름은 __Host-{앱 이름}_sid·at·csrf·login")
    void names() {
        assertThat(writer.name(KeycloakCookie.SESSION)).isEqualTo("__Host-demo_sid");
        assertThat(writer.name(KeycloakCookie.ACCESS_TOKEN)).isEqualTo("__Host-demo_at");
        assertThat(writer.name(KeycloakCookie.CSRF)).isEqualTo("__Host-demo_csrf");
        assertThat(writer.name(KeycloakCookie.LOGIN)).isEqualTo("__Host-demo_login");
    }

    @Test
    @DisplayName("COOKIE-01 쓰는 쿠키는 Secure, HttpOnly, SameSite=Lax, Path=/이고 Domain이 없다")
    void writeAttributes() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        writer.write(response, KeycloakCookie.SESSION, "c2lkLXZhbHVl", Duration.ofHours(12));

        String header = response.getHeader("Set-Cookie");
        assertThat(header).startsWith("__Host-demo_sid=c2lkLXZhbHVl;")
            .contains("; Path=/", "; Max-Age=43200", "; Secure", "; HttpOnly", "; SameSite=Lax")
            .doesNotContainIgnoringCase("domain");
    }

    @Test
    @DisplayName("COOKIE-03 수명은 초 아래를 버린다 (만료보다 늦게 남지 않게). 1초보다 짧으면 지운다")
    void maxAgeIsFloored() {
        List<String> headers = new java.util.ArrayList<>();
        for (Duration age : List.of(Duration.ofMillis(59_999), Duration.ofMillis(999), Duration.ofSeconds(-5))) {
            MockHttpServletResponse response = new MockHttpServletResponse();
            writer.write(response, KeycloakCookie.ACCESS_TOKEN, "eyJ.a.b", age);
            headers.add(response.getHeader("Set-Cookie"));
        }

        assertThat(headers.get(0)).contains("Max-Age=59;");
        assertThat(headers.get(1)).startsWith("__Host-demo_at=;").contains("Max-Age=0");
        assertThat(headers.get(2)).startsWith("__Host-demo_at=;").contains("Max-Age=0");
    }

    @Test
    @DisplayName("COOKIE-04 세션 끝: 네 쿠키 모두 같은 이름·속성·Path로 Max-Age=0")
    void clearAll() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        writer.clearAll(response);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers).hasSize(4);
        assertThat(headers).extracting(h -> h.substring(0, h.indexOf('=')))
            .containsExactly("__Host-demo_sid", "__Host-demo_at", "__Host-demo_csrf", "__Host-demo_login");
        assertThat(headers).allSatisfy(h -> assertThat(h)
            .contains("=;", "; Path=/", "; Max-Age=0", "; Secure", "; HttpOnly", "; SameSite=Lax")
            .doesNotContainIgnoringCase("domain"));

        writer.clear(response, KeycloakCookie.CSRF);
        assertThat(response.getHeaders("Set-Cookie")).as("같은 응답에서 두 번 지워도 헤더는 하나").hasSize(4);
    }

    @Test
    @DisplayName("요청에서 이름이 맞는 쿠키만 읽는다. 빈 값은 없는 것으로 본다")
    void read() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("demo_sid", "no-prefix"), new Cookie("__Host-other_sid", "other-app"),
            new Cookie("__Host-demo_sid", "mine"), new Cookie("__Host-demo_at", ""));

        assertThat(writer.read(request, KeycloakCookie.SESSION)).contains("mine");
        assertThat(writer.read(request, KeycloakCookie.ACCESS_TOKEN)).isEmpty();
        assertThat(writer.read(request, KeycloakCookie.CSRF)).isEmpty();
        assertThat(writer.read(new MockHttpServletRequest(), KeycloakCookie.SESSION)).isEmpty();
    }

    @Test
    @DisplayName("COOKIE-05 앱 이름에 공백·;·. 같은 글자가 있으면 만들지 못한다")
    void rejectsBadAppName() {
        for (String bad : new String[] {"my app", "app;x", "my.app", "", "a".repeat(33), "앱"}) {
            assertThatThrownBy(() -> new DefaultKeycloakCookieWriter(bad)).isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> new DefaultKeycloakCookieWriter(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("쿠키 값에 ; 같은 글자가 있으면 쓰지 않는다 (헤더 끼워 넣기 방지)")
    void rejectsBadValue() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        assertThatThrownBy(() -> writer.write(response, KeycloakCookie.SESSION, "a; Domain=evil.example", Duration.ofMinutes(1)))
            .isInstanceOf(IllegalArgumentException.class);
        assertThat(response.getHeaders("Set-Cookie")).isEmpty();
    }

    @Test
    @DisplayName("속성을 바꾸려면 cookie()를 덮어쓴다 (쓰기·지우기가 같이 바뀐다)")
    void overridableAttributes() {
        DefaultKeycloakCookieWriter strict = new DefaultKeycloakCookieWriter("demo") {
            @Override
            protected org.springframework.http.ResponseCookie.ResponseCookieBuilder cookie(KeycloakCookie cookie, String value) {
                return super.cookie(cookie, value).sameSite("Strict");
            }
        };
        MockHttpServletResponse response = new MockHttpServletResponse();

        strict.write(response, KeycloakCookie.CSRF, "token", Duration.ofMinutes(1));
        strict.clear(response, KeycloakCookie.CSRF);

        assertThat(response.getHeaders("Set-Cookie")).allSatisfy(h -> assertThat(h).contains("SameSite=Strict"));
    }
}
