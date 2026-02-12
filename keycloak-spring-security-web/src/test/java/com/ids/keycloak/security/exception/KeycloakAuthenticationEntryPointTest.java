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
    }

    @Nested
    class 정상_케이스 {

        @Test
        void 인증_실패_시_401_상태코드와_JSON_에러_응답을_반환한다() throws Exception {
            // Given
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
    }

    @Nested
    class 바운더리_케이스 {

        @Test
        void KeycloakSecurityException이_cause인_경우에도_동일한_응답을_반환한다() throws Exception {
            // Given
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
            // Given
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
