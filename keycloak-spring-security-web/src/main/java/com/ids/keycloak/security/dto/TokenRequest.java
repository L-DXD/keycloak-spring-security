package com.ids.keycloak.security.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * 토큰 발급 요청 DTO.
 * <p>
 * POST {prefix}/token 엔드포인트의 요청 본문.
 * </p>
 */
@Getter
@Setter
@NoArgsConstructor
public class TokenRequest {

    private String username;
    private String password;

    public TokenRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }
}
