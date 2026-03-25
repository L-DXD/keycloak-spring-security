package com.ids.keycloak.security.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * 로그아웃 요청 DTO.
 * <p>
 * POST {prefix}/logout 엔드포인트의 요청 본문.
 * </p>
 */
@Getter
@Setter
@NoArgsConstructor
public class LogoutRequest {

    private String refreshToken;

    public LogoutRequest(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}
