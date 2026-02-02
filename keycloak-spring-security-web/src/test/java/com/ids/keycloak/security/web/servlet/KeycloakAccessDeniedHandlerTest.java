package com.ids.keycloak.security.web.servlet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.config.KeycloakErrorProperties;
import com.ids.keycloak.security.error.ErrorResponse;
import com.ids.keycloak.security.exception.ErrorCode;
import com.ids.keycloak.security.exception.KeycloakSecurityException;
import com.ids.keycloak.security.exception.KeycloakAccessDeniedHandler;
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
import org.springframework.security.access.AccessDeniedException;

@ExtendWith(MockitoExtension.class)
class KeycloakAccessDeniedHandlerTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private ObjectMapper objectMapper;
    private KeycloakErrorProperties errorProperties;
    private KeycloakAccessDeniedHandler handler;
    private ByteArrayOutputStream outputStream;

    @BeforeEach
    void setUp() throws Exception {
        objectMapper = new ObjectMapper();
        errorProperties = new KeycloakErrorProperties();
        handler = new KeycloakAccessDeniedHandler(objectMapper, errorProperties);
        outputStream = new ByteArrayOutputStream();
        // lenient를 사용하여 리다이렉트 테스트에서도 에러가 발생하지 않도록 함
        lenient().when(response.getOutputStream()).thenReturn(new DelegatingServletOutputStream(outputStream));
    }

    @Nested
    class 정상_케이스 {

        @Test
        void 인가_실패_시_403_상태코드와_JSON_에러_응답을_반환한다() throws Exception {
            // Given
            AccessDeniedException accessDeniedException = new AccessDeniedException("Access denied");

            // When
            handler.handle(request, response, accessDeniedException);

            // Then
            verify(response).setStatus(403);
            verify(response).setContentType(MediaType.APPLICATION_JSON_VALUE);

            ErrorResponse errorResponse = objectMapper.readValue(outputStream.toByteArray(), ErrorResponse.class);
            assertThat(errorResponse.code()).isEqualTo("ACCESS_DENIED");
            assertThat(errorResponse.message()).isEqualTo("이 리소스에 접근할 권한이 없습니다.");
        }
    }

    @Nested
    class 바운더리_케이스 {

        @Test
        void KeycloakSecurityException이_cause인_경우에도_동일한_응답을_반환한다() throws Exception {
            // Given
            KeycloakSecurityException cause = new KeycloakSecurityException(ErrorCode.AUTHORITY_MAPPING_FAILED);
            AccessDeniedException accessDeniedException = new AccessDeniedException("Access denied", cause);

            // When
            handler.handle(request, response, accessDeniedException);

            // Then
            verify(response).setStatus(403);
            verify(response).setContentType(MediaType.APPLICATION_JSON_VALUE);

            ErrorResponse errorResponse = objectMapper.readValue(outputStream.toByteArray(), ErrorResponse.class);
            assertThat(errorResponse.code()).isEqualTo("ACCESS_DENIED");
        }

        @Test
        void cause가_null인_AccessDeniedException도_정상_처리한다() throws Exception {
            // Given
            AccessDeniedException accessDeniedException = new AccessDeniedException("No cause");

            // When
            handler.handle(request, response, accessDeniedException);

            // Then
            verify(response).setStatus(403);

            ErrorResponse errorResponse = objectMapper.readValue(outputStream.toByteArray(), ErrorResponse.class);
            assertThat(errorResponse.code()).isEqualTo("ACCESS_DENIED");
        }
    }

    @Nested
    class 리다이렉트_모드 {

        @Test
        void 리다이렉트_활성화_시_설정된_URL로_리다이렉트한다() throws Exception {
            // Given
            KeycloakErrorProperties redirectProperties = new KeycloakErrorProperties();
            redirectProperties.setRedirectEnabled(true);
            redirectProperties.setAccessDeniedRedirectUrl("/custom/error/403");
            KeycloakAccessDeniedHandler redirectHandler = new KeycloakAccessDeniedHandler(objectMapper, redirectProperties);

            AccessDeniedException accessDeniedException = new AccessDeniedException("Access denied");

            // When
            redirectHandler.handle(request, response, accessDeniedException);

            // Then
            verify(response).sendRedirect("/custom/error/403");
        }

        @Test
        void 리다이렉트_활성화_시_기본_URL로_리다이렉트한다() throws Exception {
            // Given
            KeycloakErrorProperties redirectProperties = new KeycloakErrorProperties();
            redirectProperties.setRedirectEnabled(true);
            // 기본값: /error/403
            KeycloakAccessDeniedHandler redirectHandler = new KeycloakAccessDeniedHandler(objectMapper, redirectProperties);

            AccessDeniedException accessDeniedException = new AccessDeniedException("Access denied");

            // When
            redirectHandler.handle(request, response, accessDeniedException);

            // Then
            verify(response).sendRedirect("/error/403");
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
            KeycloakAccessDeniedHandler ajaxHandler = new KeycloakAccessDeniedHandler(objectMapper, ajaxProperties);

            when(request.getHeader("X-Requested-With")).thenReturn("XMLHttpRequest");

            AccessDeniedException accessDeniedException = new AccessDeniedException("Access denied");

            // When
            ajaxHandler.handle(request, response, accessDeniedException);

            // Then
            verify(response).setStatus(403);
            verify(response).setContentType(MediaType.APPLICATION_JSON_VALUE);
        }

        @Test
        void Accept_헤더가_application_json이면_AJAX_요청으로_처리한다() throws Exception {
            // Given
            KeycloakErrorProperties ajaxProperties = new KeycloakErrorProperties();
            ajaxProperties.setRedirectEnabled(true);
            ajaxProperties.setAjaxReturnsJson(true);
            KeycloakAccessDeniedHandler ajaxHandler = new KeycloakAccessDeniedHandler(objectMapper, ajaxProperties);

            // X-Requested-With가 null이고 Accept가 application/json인 경우
            when(request.getHeader("X-Requested-With")).thenReturn(null);
            when(request.getHeader("Accept")).thenReturn("application/json");

            AccessDeniedException accessDeniedException = new AccessDeniedException("Access denied");

            // When
            ajaxHandler.handle(request, response, accessDeniedException);

            // Then
            verify(response).setStatus(403);
            verify(response).setContentType(MediaType.APPLICATION_JSON_VALUE);
        }

        @Test
        void ajaxReturnsJson이_false면_AJAX_요청도_리다이렉트한다() throws Exception {
            // Given
            KeycloakErrorProperties properties = new KeycloakErrorProperties();
            properties.setRedirectEnabled(true);
            properties.setAjaxReturnsJson(false);
            KeycloakAccessDeniedHandler handler = new KeycloakAccessDeniedHandler(objectMapper, properties);

            // ajaxReturnsJson이 false이므로 AJAX 요청 여부를 체크하지 않음 - stubbing 불필요

            AccessDeniedException accessDeniedException = new AccessDeniedException("Access denied");

            // When
            handler.handle(request, response, accessDeniedException);

            // Then
            verify(response).sendRedirect("/error/403");
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
