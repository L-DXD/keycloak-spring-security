package com.ids.keycloak.security.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;

/**
 * 토큰 발급/갱신 응답 DTO.
 */
@Getter
@Builder
public class TokenResponse {

    @JsonProperty("access_token")
    private final String accessToken;

    @JsonProperty("refresh_token")
    private final String refreshToken;

    @JsonProperty("token_type")
    private final String tokenType;

    @JsonProperty("expires_in")
    private final Integer expiresIn;

    @JsonProperty("refresh_expires_in")
    private final Integer refreshExpiresIn;
}
