package com.ids.keycloak.security.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * AuthenticationMethodDetector 단위 테스트.
 * 판별 매트릭스의 각 케이스와 우선순위를 검증합니다.
 */
class AuthenticationMethodDetectorTest {

    private AuthenticationMethodDetector detector;

    @BeforeEach
    void setUp() {
        detector = new AuthenticationMethodDetector(List.of("/api/keycloak/login"));
    }

    // ======================================================================
    // 1. 기본 판별 케이스
    // ======================================================================

    @Nested
    class Bearer_헤더_판별 {

        @Test
        void Authorization_Bearer_헤더가_있으면_BEARER를_반환한다() {
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("Authorization", "Bearer eyJhbGciOiJSUzI1NiIs...");

            assertThat(detector.detect(request)).isEqualTo(AuthenticationMethod.BEARER);
        }

        @Test
        void Bearer_prefix가_정확히_일치해야_한다() {
            // "Bearer"만 있고 공백 없는 경우는 Bearer로 판별되지 않아야 함
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("Authorization", "Bearertoken");

            assertThat(detector.detect(request)).isNotEqualTo(AuthenticationMethod.BEARER);
        }
    }

    @Nested
    class Basic_헤더_판별 {

        @Test
        void Authorization_Basic_헤더가_있으면_BASIC을_반환한다() {
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("Authorization", "Basic dXNlcjpwYXNz");

            assertThat(detector.detect(request)).isEqualTo(AuthenticationMethod.BASIC);
        }
    }

    @Nested
    class CREDENTIAL_LOGIN_판별 {

        @Test
        void POST_메서드_와_기본_loginPath_요청은_CREDENTIAL_LOGIN을_반환한다() {
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/keycloak/login");

            assertThat(detector.detect(request)).isEqualTo(AuthenticationMethod.CREDENTIAL_LOGIN);
        }

        @Test
        void GET_메서드_이면_loginPath라도_CREDENTIAL_LOGIN이_아니다() {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/keycloak/login");

            assertThat(detector.detect(request)).isNotEqualTo(AuthenticationMethod.CREDENTIAL_LOGIN);
        }

        @Test
        void POST_메서드라도_loginPath가_아니면_CREDENTIAL_LOGIN이_아니다() {
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/other");

            assertThat(detector.detect(request)).isNotEqualTo(AuthenticationMethod.CREDENTIAL_LOGIN);
        }

        @Test
        void 커스텀_loginPaths_주입_시_해당_경로도_CREDENTIAL_LOGIN으로_판별된다() {
            AuthenticationMethodDetector customDetector = new AuthenticationMethodDetector(
                List.of("/api/keycloak/login", "/custom/auth/login")
            );
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/custom/auth/login");

            assertThat(customDetector.detect(request)).isEqualTo(AuthenticationMethod.CREDENTIAL_LOGIN);
        }

        @Test
        void PUT_메서드는_loginPath라도_CREDENTIAL_LOGIN이_아니다() {
            MockHttpServletRequest request = new MockHttpServletRequest("PUT", "/api/keycloak/login");
            assertThat(detector.detect(request)).isNotEqualTo(AuthenticationMethod.CREDENTIAL_LOGIN);
        }

        @Test
        void DELETE_메서드는_loginPath라도_CREDENTIAL_LOGIN이_아니다() {
            MockHttpServletRequest request = new MockHttpServletRequest("DELETE", "/api/keycloak/login");
            assertThat(detector.detect(request)).isNotEqualTo(AuthenticationMethod.CREDENTIAL_LOGIN);
        }
    }

    @Nested
    class OIDC_COOKIE_판별 {

        @Test
        void access_token_쿠키만_있으면_OIDC_COOKIE를_반환한다() {
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setCookies(new jakarta.servlet.http.Cookie("access_token", "access-token-value"));

            assertThat(detector.detect(request)).isEqualTo(AuthenticationMethod.OIDC_COOKIE);
        }

        @Test
        void id_token_쿠키만_있으면_OIDC_COOKIE를_반환한다() {
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setCookies(new jakarta.servlet.http.Cookie("id_token", "id-token-value"));

            assertThat(detector.detect(request)).isEqualTo(AuthenticationMethod.OIDC_COOKIE);
        }

        @Test
        void access_token과_id_token_쿠키_둘_다_있으면_OIDC_COOKIE를_반환한다() {
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setCookies(
                new jakarta.servlet.http.Cookie("access_token", "access-token-value"),
                new jakarta.servlet.http.Cookie("id_token", "id-token-value")
            );

            assertThat(detector.detect(request)).isEqualTo(AuthenticationMethod.OIDC_COOKIE);
        }
    }

    @Nested
    class NONE_판별 {

        @Test
        void 헤더도_쿠키도_없으면_NONE을_반환한다() {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/resource");

            assertThat(detector.detect(request)).isEqualTo(AuthenticationMethod.NONE);
        }

        @Test
        void 쿠키가_없는_배열이면_NONE을_반환한다() {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/resource");
            // 쿠키 명시적으로 비워두기 (setCookies 미호출)

            assertThat(detector.detect(request)).isEqualTo(AuthenticationMethod.NONE);
        }
    }

    // ======================================================================
    // 2. 우선순위 핵심 케이스
    // ======================================================================

    @Nested
    class 우선순위_검증 {

        @Test
        void Bearer_헤더와_OIDC_쿠키가_동시에_있으면_BEARER가_우선된다() {
            // Bearer + 쿠키 동시 존재 → BEARER 우선 (우선순위 핵심)
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("Authorization", "Bearer eyJhbGciOiJSUzI1NiIs...");
            request.setCookies(new jakarta.servlet.http.Cookie("access_token", "access-token-value"));

            assertThat(detector.detect(request)).isEqualTo(AuthenticationMethod.BEARER);
        }

        @Test
        void Basic_헤더와_OIDC_쿠키가_동시에_있으면_BASIC이_우선된다() {
            // Basic + 쿠키 동시 존재 → BASIC 우선
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("Authorization", "Basic dXNlcjpwYXNz");
            request.setCookies(new jakarta.servlet.http.Cookie("access_token", "access-token-value"));

            assertThat(detector.detect(request)).isEqualTo(AuthenticationMethod.BASIC);
        }

        @Test
        void Bearer_헤더와_loginPath가_동시에_있으면_BEARER가_우선된다() {
            // POST loginPath + Bearer 헤더 → BEARER 우선
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/keycloak/login");
            request.addHeader("Authorization", "Bearer eyJhbGciOiJSUzI1NiIs...");

            assertThat(detector.detect(request)).isEqualTo(AuthenticationMethod.BEARER);
        }

        @Test
        void CREDENTIAL_LOGIN_경로가_OIDC_쿠키보다_우선된다() {
            // POST loginPath + OIDC 쿠키 → CREDENTIAL_LOGIN 우선 (쿠키보다 URI 판별이 먼저)
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/keycloak/login");
            request.setCookies(new jakarta.servlet.http.Cookie("access_token", "access-token-value"));

            assertThat(detector.detect(request)).isEqualTo(AuthenticationMethod.CREDENTIAL_LOGIN);
        }

        @Test
        void 판별_순서는_Bearer_Basic_CREDENTIAL_LOGIN_OIDC_NONE_순이다() {
            // Bearer 최우선 검증 (모든 조건 동시 충족)
            MockHttpServletRequest requestWithAll = new MockHttpServletRequest("POST", "/api/keycloak/login");
            requestWithAll.addHeader("Authorization", "Bearer eyJhbGciOiJSUzI1NiIs...");
            requestWithAll.setCookies(new jakarta.servlet.http.Cookie("access_token", "at"));

            assertThat(detector.detect(requestWithAll)).isEqualTo(AuthenticationMethod.BEARER);
        }
    }

    // ======================================================================
    // 3. null 경계값
    // ======================================================================

    @Nested
    class 경계_케이스 {

        @Test
        void null_loginPaths_주입_시_기본_경로로_동작한다() {
            AuthenticationMethodDetector detectorWithNull = new AuthenticationMethodDetector(null);
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/keycloak/login");

            assertThat(detectorWithNull.detect(request)).isEqualTo(AuthenticationMethod.CREDENTIAL_LOGIN);
        }

        @Test
        void 빈_loginPaths_주입_시_CREDENTIAL_LOGIN이_판별되지_않는다() {
            AuthenticationMethodDetector detectorWithEmpty = new AuthenticationMethodDetector(List.of());
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/keycloak/login");

            assertThat(detectorWithEmpty.detect(request)).isNotEqualTo(AuthenticationMethod.CREDENTIAL_LOGIN);
        }
    }
}
