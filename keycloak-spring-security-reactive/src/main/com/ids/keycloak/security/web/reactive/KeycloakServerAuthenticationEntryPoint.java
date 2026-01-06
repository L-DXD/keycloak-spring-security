
package com.ids.keycloak.security.web.reactive;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.error.ErrorResponse;
import com.ids.keycloak.security.exception.ErrorCode;
import com.ids.keycloak.security.exception.KeycloakSecurityException;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Reactive 환경에서 인증(Authentication) 과정에서 실패하는 경우 호출되는 핸들러
 */
@RequiredArgsConstructor
public class KeycloakServerAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
        return Mono.defer(() -> {
            ServerHttpResponse response = exchange.getResponse();
            response.getHeaders().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);

            ErrorCode errorCode;
            String message;

            if (ex.getCause() instanceof KeycloakSecurityException) {
                KeycloakSecurityException cause = (KeycloakSecurityException) ex.getCause();
                errorCode = cause.getErrorCode();
                message = errorCode.getDefaultMessage();
            } else {
                errorCode = ErrorCode.AUTHENTICATION_FAILED;
                message = ex.getMessage();
            }

            response.setRawStatusCode(errorCode.getHttpStatus());

            try {
                byte[] bytes = objectMapper.writeValueAsBytes(new ErrorResponse(errorCode.getCode(), message));
                DataBuffer buffer = response.bufferFactory().wrap(bytes);
                return response.writeWith(Mono.just(buffer));
            } catch (JsonProcessingException e) {
                // 직렬화 실패 시, 내부 서버 에러로 처리
                response.setRawStatusCode(ErrorCode.CONFIGURATION_ERROR.getHttpStatus());
                byte[] bytes = getFallbackErrorResponse(ErrorCode.CONFIGURATION_ERROR);
                DataBuffer buffer = response.bufferFactory().wrap(bytes);
                return response.writeWith(Mono.just(buffer));
            }
        });
    }

    private byte[] getFallbackErrorResponse(ErrorCode errorCode) {
        try {
            return objectMapper.writeValueAsBytes(new ErrorResponse(errorCode.getCode(), errorCode.getDefaultMessage()));
        } catch (JsonProcessingException e) {
            // ObjectMapper가 완전 실패하는 최악의 경우를 대비한 텍스트 기반 응답
            return String.format("{\"code\":\"%s\",\"message\":\"%s\"}", errorCode.getCode(), errorCode.getDefaultMessage()).getBytes();
        }
    }
}
