
package com.ids.keycloak.security.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.error.ErrorResponse;
import com.ids.keycloak.security.exception.ErrorCode;
import com.ids.keycloak.security.exception.KeycloakSecurityException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ResolvableType;
import org.springframework.core.codec.EncodingException;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.codec.json.Jackson2JsonEncoder;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Collections;

/**
 * Reactive 환경에서 인증(Authentication) 과정에서 실패하는 경우 호출되는 핸들러
 */
@Slf4j
@RequiredArgsConstructor
public class KeycloakServerAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
        return Mono.defer(() -> {
           if (ex.getCause() instanceof KeycloakSecurityException cause) {
              log.debug("KeycloakServerAuthenticationEntryPoint: 인증 실패 - KeycloakSecurityException 발생 = {}, {}", cause.getErrorCode(), cause.getMessage());
           }
            ServerHttpResponse response = exchange.getResponse();
            response.getHeaders().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);

            ErrorCode errorCode = ErrorCode.AUTHENTICATION_FAILED;
            response.setRawStatusCode(errorCode.getHttpStatus());

            ErrorResponse errorResponse = new ErrorResponse(errorCode.getCode(), errorCode.getDefaultMessage());

            return writeErrorResponse(response, errorResponse)
                    .onErrorResume(EncodingException.class, e -> {
                        // 주 응답 직렬화 실패 시, 대체 응답 시도
                        log.warn("메인 에러 응답 작성 중 오류 발생, 대체 응답을 시도합니다.", e);
                        ErrorCode fallbackErrorCode = ErrorCode.CONFIGURATION_ERROR;
                        response.setRawStatusCode(fallbackErrorCode.getHttpStatus());
                        ErrorResponse fallbackResponse = new ErrorResponse(fallbackErrorCode.getCode(), fallbackErrorCode.getDefaultMessage());

                        // 대체 응답 작성 시도
                        return writeErrorResponse(response, fallbackResponse)
                                .onErrorResume(fallbackEx -> {
                                    // 대체 응답도 실패하면, 하드코딩된 문자열 사용
                                    log.error("대체 에러 응답 작성 중 오류 발생, 원시 문자열을 사용합니다.", fallbackEx);
                                    byte[] bytes = getUltimateFallbackResponseBytes(fallbackErrorCode);
                                    DataBuffer buffer = response.bufferFactory().wrap(bytes);
                                    return response.writeWith(Mono.just(buffer));
                                });
                    });
        });
    }

    private Mono<Void> writeErrorResponse(ServerHttpResponse response, ErrorResponse errorResponse) {
        Jackson2JsonEncoder encoder = new Jackson2JsonEncoder(objectMapper);
        return response.writeWith(encoder.encode(
                Mono.just(errorResponse),
                response.bufferFactory(),
                ResolvableType.forInstance(errorResponse),
                MediaType.APPLICATION_JSON,
                Collections.emptyMap()
        ));
    }

    private byte[] getUltimateFallbackResponseBytes(ErrorCode errorCode) {
        return String.format("{\"code\":\"%s\",\"message\":\"%s\"}", errorCode.getCode(), errorCode.getDefaultMessage()).getBytes();
    }
}
