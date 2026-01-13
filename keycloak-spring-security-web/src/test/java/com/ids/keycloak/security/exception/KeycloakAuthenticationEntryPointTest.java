package com.ids.keycloak.security.exception;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
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
    private KeycloakAuthenticationEntryPoint entryPoint;
    private ByteArrayOutputStream outputStream;

    @BeforeEach
    void setUp() throws Exception {
        objectMapper = new ObjectMapper();
        entryPoint = new KeycloakAuthenticationEntryPoint(objectMapper);
        outputStream = new ByteArrayOutputStream();
        when(response.getOutputStream()).thenReturn(new DelegatingServletOutputStream(outputStream));
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
