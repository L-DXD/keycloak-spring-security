package com.ids.keycloak.security.exception;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.config.KeycloakErrorProperties;
import com.ids.keycloak.security.error.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;

@ExtendWith(MockitoExtension.class)
class KeycloakAuthenticationEntryPointTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private ObjectMapper objectMapper;
    private KeycloakErrorProperties errorProperties;
    private KeycloakAuthenticationEntryPoint entryPoint;
    private ByteArrayOutputStream outputStream;

    @BeforeEach
    void setUp() throws Exception {
        objectMapper = new ObjectMapper();
        errorProperties = new KeycloakErrorProperties();
        entryPoint = new KeycloakAuthenticationEntryPoint(objectMapper, errorProperties);
        outputStream = new ByteArrayOutputStream();
        // lenient를 사용하여 리다이렉트 테스트에서도 에러가 발생하지 않도록 함
        lenient().when(response.getOutputStream()).thenReturn(new DelegatingServletOutputStream(outputStream));
        // Bearer Token 분기를 위해 Authorization 헤더 기본값 설정 (null = Bearer 아님)
        lenient().when(request.getHeader("Authorization")).thenReturn(null);
        // H-A: buildOAuth2AuthorizationUrl이 request.getContextPath()를 prefix로 사용한다.
        // 실제 서블릿 컨테이너는 context-path가 없으면 빈 문자열을 반환하므로 그 기본값을 재현한다
        // (Mockito mock의 기본값 null과 달리, null이면 "null/oauth2/..." 문자열이 생성되어 버린다).
        lenient().when(request.getContextPath()).thenReturn("");
    }

    @Nested
    class 정상_케이스 {

        @Test
        void 인증_실패_시_401_상태코드와_JSON_에러_응답을_반환한다() throws Exception {
            // Given: AJAX 요청(JSON 클라이언트)이어야 401 JSON 분기를 탄다.
            // (C-1: redirectEnabled=false 기본 상태에서 비-AJAX 요청은 오히려 OAuth2 로그인으로
            // 리다이렉트된다 — 아래 AJAX_요청_처리, 리다이렉트_모드 참고)
            lenient().when(request.getHeader("Accept")).thenReturn(MediaType.APPLICATION_JSON_VALUE);
            AuthenticationException authException = new BadCredentialsException("Invalid credentials");

            // When
            entryPoint.commence(request, response, authException);

            // Then
            verify(response).setStatus(401);
            verify(response).setContentType(MediaType.APPLICATION_JSON_VALUE);

            ErrorResponse errorResponse = objectMapper.readValue(outputStream.toByteArray(), ErrorResponse.class);
            assertThat(errorResponse.code()).isEqualTo("AUTHENTICATION_FAILED");
            assertThat(errorResponse.message()).isEqualTo("유효하지 않은 자격 증명 또는 토큰으로 인해 인증에 실패했습니다.");
        }

        @Test
        void Accept_text_html을_명시한_브라우저_요청은_기본적으로_OAuth2_로그인으로_리다이렉트한다() throws Exception {
            // Given: C-1 회귀 수정 — redirectEnabled=false(기본) 상태에서 Accept: text/html을 명시한
            // 브라우저의 HTML 네비게이션 요청은 401 JSON이 아니라 authorization endpoint로
            // 리다이렉트되어야 기존 SSO 로그인 플로우가 유지된다. H-B: 판정 기준은
            // acceptsHtmlExplicitly이므로 이 케이스는 Accept 헤더를 명시적으로 text/html로 설정한다.
            lenient().when(request.getHeader("Accept")).thenReturn(MediaType.TEXT_HTML_VALUE);
            AuthenticationException authException = new BadCredentialsException("Invalid credentials");

            // When
            entryPoint.commence(request, response, authException);

            // Then
            verify(response).sendRedirect("/oauth2/authorization/keycloak");
        }

        @Test
        void Accept_헤더가_없는_요청은_H_B에_따라_401_JSON을_반환한다() throws Exception {
            // Given: H-B 회귀 수정 — curl 기본 요청·서버간 호출처럼 Accept 헤더가 없는 요청은
            // "AJAX가 아니면 브라우저"가 아니라 "Accept: text/html을 실제로 명시했을 때만 브라우저"
            // 기준(acceptsHtmlExplicitly)으로 판정되어 302 리다이렉트 대신 401 JSON을 받아야 한다.
            AuthenticationException authException = new BadCredentialsException("Invalid credentials");

            // When
            entryPoint.commence(request, response, authException);

            // Then
            verify(response).setStatus(401);
            verify(response).setContentType(MediaType.APPLICATION_JSON_VALUE);
            verify(response, org.mockito.Mockito.never()).sendRedirect(org.mockito.ArgumentMatchers.anyString());
        }

        @Test
        void Accept가_wildcard_단독인_요청도_H_B에_따라_401_JSON을_반환한다() throws Exception {
            // Given: curl -H "Accept: */*" 등 명시적 와일드카드 단독도 브라우저 신호로 보지 않는다.
            lenient().when(request.getHeader("Accept")).thenReturn(MediaType.ALL_VALUE);
            AuthenticationException authException = new BadCredentialsException("Invalid credentials");

            // When
            entryPoint.commence(request, response, authException);

            // Then
            verify(response).setStatus(401);
            verify(response, org.mockito.Mockito.never()).sendRedirect(org.mockito.ArgumentMatchers.anyString());
        }
    }

    @Nested
    class 바운더리_케이스 {

        @Test
        void KeycloakSecurityException이_cause인_경우에도_동일한_응답을_반환한다() throws Exception {
            // Given: AJAX 요청이어야 401 JSON 분기를 탄다 (C-1, 위 정상_케이스 주석 참고)
            lenient().when(request.getHeader("Accept")).thenReturn(MediaType.APPLICATION_JSON_VALUE);
            KeycloakSecurityException cause = new KeycloakSecurityException(ErrorCode.REFRESH_TOKEN_NOT_FOUND);
            AuthenticationException authException = new BadCredentialsException("Auth failed", cause);

            // When
            entryPoint.commence(request, response, authException);

            // Then
            verify(response).setStatus(401);
            verify(response).setContentType(MediaType.APPLICATION_JSON_VALUE);

            ErrorResponse errorResponse = objectMapper.readValue(outputStream.toByteArray(), ErrorResponse.class);
            assertThat(errorResponse.code()).isEqualTo("AUTHENTICATION_FAILED");
        }

        @Test
        void cause가_null인_AuthenticationException도_정상_처리한다() throws Exception {
            // Given: AJAX 요청이어야 401 JSON 분기를 탄다 (C-1, 위 정상_케이스 주석 참고)
            lenient().when(request.getHeader("Accept")).thenReturn(MediaType.APPLICATION_JSON_VALUE);
            AuthenticationException authException = new BadCredentialsException("No cause");

            // When
            entryPoint.commence(request, response, authException);

            // Then
            verify(response).setStatus(401);

            ErrorResponse errorResponse = objectMapper.readValue(outputStream.toByteArray(), ErrorResponse.class);
            assertThat(errorResponse.code()).isEqualTo("AUTHENTICATION_FAILED");
        }
    }

    @Nested
    class 리다이렉트_모드 {

        @Test
        void 리다이렉트_활성화_시_설정된_URL로_리다이렉트한다() throws Exception {
            // Given
            KeycloakErrorProperties redirectProperties = new KeycloakErrorProperties();
            redirectProperties.setRedirectEnabled(true);
            redirectProperties.setAuthenticationFailedRedirectUrl("/custom/login");
            KeycloakAuthenticationEntryPoint redirectEntryPoint = new KeycloakAuthenticationEntryPoint(objectMapper, redirectProperties);

            AuthenticationException authException = new BadCredentialsException("Invalid credentials");

            // When
            redirectEntryPoint.commence(request, response, authException);

            // Then
            verify(response).sendRedirect("/custom/login");
        }

        @Test
        void 리다이렉트_활성화_시_기본_URL로_리다이렉트한다() throws Exception {
            // Given
            KeycloakErrorProperties redirectProperties = new KeycloakErrorProperties();
            redirectProperties.setRedirectEnabled(true);
            // 기본값: /login
            KeycloakAuthenticationEntryPoint redirectEntryPoint = new KeycloakAuthenticationEntryPoint(objectMapper, redirectProperties);

            AuthenticationException authException = new BadCredentialsException("Invalid credentials");

            // When
            redirectEntryPoint.commence(request, response, authException);

            // Then
            verify(response).sendRedirect("/login");
        }
    }

    @Nested
    class AJAX_요청_처리 {

        @Test
        void AJAX_요청_시_ajaxReturnsJson이_true면_JSON_응답을_반환한다() throws Exception {
            // Given
            KeycloakErrorProperties ajaxProperties = new KeycloakErrorProperties();
            ajaxProperties.setRedirectEnabled(true);
            ajaxProperties.setAjaxReturnsJson(true);
            KeycloakAuthenticationEntryPoint ajaxEntryPoint = new KeycloakAuthenticationEntryPoint(objectMapper, ajaxProperties);

            when(request.getHeader("X-Requested-With")).thenReturn("XMLHttpRequest");

            AuthenticationException authException = new BadCredentialsException("Invalid credentials");

            // When
            ajaxEntryPoint.commence(request, response, authException);

            // Then
            verify(response).setStatus(401);
            verify(response).setContentType(MediaType.APPLICATION_JSON_VALUE);
        }

        @Test
        void Accept_헤더가_application_json이면_AJAX_요청으로_처리한다() throws Exception {
            // Given
            KeycloakErrorProperties ajaxProperties = new KeycloakErrorProperties();
            ajaxProperties.setRedirectEnabled(true);
            ajaxProperties.setAjaxReturnsJson(true);
            KeycloakAuthenticationEntryPoint ajaxEntryPoint = new KeycloakAuthenticationEntryPoint(objectMapper, ajaxProperties);

            // X-Requested-With가 null이고 Accept가 application/json인 경우
            when(request.getHeader("X-Requested-With")).thenReturn(null);
            when(request.getHeader("Accept")).thenReturn("application/json");

            AuthenticationException authException = new BadCredentialsException("Invalid credentials");

            // When
            ajaxEntryPoint.commence(request, response, authException);

            // Then
            verify(response).setStatus(401);
            verify(response).setContentType(MediaType.APPLICATION_JSON_VALUE);
        }

        @Test
        void ajaxReturnsJson이_false면_AJAX_요청도_리다이렉트한다() throws Exception {
            // Given
            KeycloakErrorProperties properties = new KeycloakErrorProperties();
            properties.setRedirectEnabled(true);
            properties.setAjaxReturnsJson(false);
            KeycloakAuthenticationEntryPoint entryPoint = new KeycloakAuthenticationEntryPoint(objectMapper, properties);

            // ajaxReturnsJson이 false이므로 AJAX 요청 여부를 체크하지 않음 - stubbing 불필요

            AuthenticationException authException = new BadCredentialsException("Invalid credentials");

            // When
            entryPoint.commence(request, response, authException);

            // Then
            verify(response).sendRedirect("/login");
        }
    }

    @Nested
    class Basic_Auth_처리 {

        @Test
        void Basic_Auth_활성화_시_Basic_요청에_WWW_Authenticate_헤더를_포함한다() throws Exception {
            // Given
            KeycloakAuthenticationEntryPoint basicEntryPoint = new KeycloakAuthenticationEntryPoint(
                objectMapper, errorProperties, true, "test-realm"
            );
            when(request.getHeader("Authorization")).thenReturn("Basic dXNlcjpwYXNz");

            AuthenticationException authException = new BadCredentialsException("Invalid credentials");

            // When
            basicEntryPoint.commence(request, response, authException);

            // Then
            verify(response).setHeader("WWW-Authenticate", "Basic realm=\"test-realm\"");
            verify(response).setStatus(401);
        }

        @Test
        void Basic_Auth_비활성화_시_WWW_Authenticate_헤더를_포함하지_않는다() throws Exception {
            // Given (기본 entryPoint는 basicAuthEnabled=false)
            AuthenticationException authException = new BadCredentialsException("Invalid credentials");

            // When
            entryPoint.commence(request, response, authException);

            // Then
            verify(response, org.mockito.Mockito.never()).setHeader(
                org.mockito.ArgumentMatchers.eq("WWW-Authenticate"),
                org.mockito.ArgumentMatchers.anyString()
            );
        }

        @Test
        void Basic_Auth_활성화_시_Basic_헤더_없는_요청에는_WWW_Authenticate를_추가하지_않는다() throws Exception {
            // Given
            KeycloakAuthenticationEntryPoint basicEntryPoint = new KeycloakAuthenticationEntryPoint(
                objectMapper, errorProperties, true, "test-realm"
            );
            when(request.getHeader("Authorization")).thenReturn(null);

            AuthenticationException authException = new BadCredentialsException("Invalid credentials");

            // When
            basicEntryPoint.commence(request, response, authException);

            // Then
            verify(response, org.mockito.Mockito.never()).setHeader(
                org.mockito.ArgumentMatchers.eq("WWW-Authenticate"),
                org.mockito.ArgumentMatchers.anyString()
            );
        }

        @Test
        void realmName이_null이면_기본값_keycloak을_사용한다() throws Exception {
            // Given
            KeycloakAuthenticationEntryPoint basicEntryPoint = new KeycloakAuthenticationEntryPoint(
                objectMapper, errorProperties, true, null
            );
            when(request.getHeader("Authorization")).thenReturn("Basic dXNlcjpwYXNz");

            AuthenticationException authException = new BadCredentialsException("Invalid credentials");

            // When
            basicEntryPoint.commence(request, response, authException);

            // Then
            verify(response).setHeader("WWW-Authenticate", "Basic realm=\"keycloak\"");
        }
    }

    @Nested
    class 세션_만료_처리 {

        @Test
        void 세션_만료_시_sessionExpiredRedirectUrl로_리다이렉트한다() throws Exception {
            // Given
            KeycloakErrorProperties properties = new KeycloakErrorProperties();
            properties.setRedirectEnabled(true);
            properties.setSessionExpiredRedirectUrl("/login?expired=true");
            KeycloakAuthenticationEntryPoint entryPoint = new KeycloakAuthenticationEntryPoint(objectMapper, properties);

            // 세션 만료 상황 시뮬레이션: requestedSessionId가 있지만 세션이 null (session == null이면 isRequestedSessionIdValid는 호출 안됨)
            when(request.getRequestedSessionId()).thenReturn("expired-session-id");
            when(request.getSession(false)).thenReturn(null);

            AuthenticationException authException = new BadCredentialsException("Session expired");

            // When
            entryPoint.commence(request, response, authException);

            // Then
            verify(response).sendRedirect("/login?expired=true");
        }

        @Test
        void 세션_만료_URL_미설정_시_authenticationFailedRedirectUrl로_리다이렉트한다() throws Exception {
            // Given
            KeycloakErrorProperties properties = new KeycloakErrorProperties();
            properties.setRedirectEnabled(true);
            properties.setAuthenticationFailedRedirectUrl("/custom/login");
            // sessionExpiredRedirectUrl 미설정
            KeycloakAuthenticationEntryPoint entryPoint = new KeycloakAuthenticationEntryPoint(objectMapper, properties);

            // 세션 만료 상황 시뮬레이션: requestedSessionId가 있지만 세션이 null
            when(request.getRequestedSessionId()).thenReturn("expired-session-id");
            when(request.getSession(false)).thenReturn(null);

            AuthenticationException authException = new BadCredentialsException("Session expired");

            // When
            entryPoint.commence(request, response, authException);

            // Then
            verify(response).sendRedirect("/custom/login");
        }
    }

    @Nested
    class H_A_context_path_리다이렉트 {

        @Test
        void context_path가_있으면_OAuth2_로그인_리다이렉트_URL에_prefix가_붙는다() throws Exception {
            // Given: /myapp로 배포된 애플리케이션에서 미인증 브라우저(Accept: text/html) 요청.
            when(request.getContextPath()).thenReturn("/myapp");
            lenient().when(request.getHeader("Accept")).thenReturn(MediaType.TEXT_HTML_VALUE);
            AuthenticationException authException = new BadCredentialsException("Invalid credentials");

            // When
            entryPoint.commence(request, response, authException);

            // Then
            verify(response).sendRedirect("/myapp/oauth2/authorization/keycloak");
        }
    }

    @Nested
    class C_B_자기참조_가드 {

        @Test
        void authorization_엔드포인트_자체_요청은_다시_리다이렉트되지_않고_401_JSON을_반환한다() throws Exception {
            // Given: 예외적인 필터 순서 구성으로 /oauth2/authorization/keycloak 자체가 미인증으로
            // 이 EntryPoint까지 도달한 경우, 다시 같은 URL로 리다이렉트하면 무한 루프가 된다.
            when(request.getRequestURI()).thenReturn("/oauth2/authorization/keycloak");
            lenient().when(request.getHeader("Accept")).thenReturn(MediaType.TEXT_HTML_VALUE);
            AuthenticationException authException = new BadCredentialsException("Invalid credentials");

            // When
            entryPoint.commence(request, response, authException);

            // Then
            verify(response, org.mockito.Mockito.never()).sendRedirect(org.mockito.ArgumentMatchers.anyString());
            verify(response).setStatus(401);
        }

        @Test
        void 콜백_경로_자체_요청도_다시_리다이렉트되지_않고_401_JSON을_반환한다() throws Exception {
            // Given
            when(request.getRequestURI()).thenReturn("/login/oauth2/code/keycloak");
            lenient().when(request.getHeader("Accept")).thenReturn(MediaType.TEXT_HTML_VALUE);
            AuthenticationException authException = new BadCredentialsException("Invalid credentials");

            // When
            entryPoint.commence(request, response, authException);

            // Then
            verify(response, org.mockito.Mockito.never()).sendRedirect(org.mockito.ArgumentMatchers.anyString());
            verify(response).setStatus(401);
        }
    }

    /**
     * ServletOutputStream을 ByteArrayOutputStream으로 위임하는 헬퍼 클래스
     */
    private static class DelegatingServletOutputStream extends jakarta.servlet.ServletOutputStream {
        private final ByteArrayOutputStream target;

        DelegatingServletOutputStream(ByteArrayOutputStream target) {
            this.target = target;
        }

        @Override
        public void write(int b) {
            target.write(b);
        }

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setWriteListener(jakarta.servlet.WriteListener writeListener) {
        }
    }
}
