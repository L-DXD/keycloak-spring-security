package com.ids.keycloak.security.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * 토큰 갱신 요청 DTO.
 * <p>
 * POST {prefix}/refresh 엔드포인트의 요청 본문.
 * </p>
 */
@Getter
@Setter
@NoArgsConstructor
public class RefreshRequest {

    private String refreshToken;

    public RefreshRequest(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}
