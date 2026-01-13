package com.ids.keycloak.security.web.servlet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.error.ErrorResponse;
import com.ids.keycloak.security.exception.ErrorCode;
import com.ids.keycloak.security.exception.KeycloakSecurityException;
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
    private KeycloakAccessDeniedHandler handler;
    private ByteArrayOutputStream outputStream;

    @BeforeEach
    void setUp() throws Exception {
        objectMapper = new ObjectMapper();
        handler = new KeycloakAccessDeniedHandler(objectMapper);
        outputStream = new ByteArrayOutputStream();
        when(response.getOutputStream()).thenReturn(new DelegatingServletOutputStream(outputStream));
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
