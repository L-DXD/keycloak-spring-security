package com.ids.keycloak.security.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Bearer Token 발급 요청 DTO (Resource Owner Password Credentials).
 *
 * <p>servlet 모듈의 {@code TokenRequest}와 동일한 계약이나,
 * 모듈 분리 원칙에 따라 webflux 모듈에 별도 정의합니다.</p>
 */
public record ReactiveTokenRequest(
    @NotBlank(message = "username은 필수입니다.") String username,
    @NotBlank(message = "password는 필수입니다.") String password
) {
}
