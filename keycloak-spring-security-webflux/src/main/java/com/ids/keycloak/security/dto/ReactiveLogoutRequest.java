package com.ids.keycloak.security.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Bearer Token 로그아웃 요청 DTO.
 *
 * <p>servlet 모듈의 {@code LogoutRequest}와 동일한 계약이나,
 * 모듈 분리 원칙에 따라 webflux 모듈에 별도 정의합니다.</p>
 */
public record ReactiveLogoutRequest(
    @NotBlank(message = "refreshToken은 필수입니다.") String refreshToken
) {
}
