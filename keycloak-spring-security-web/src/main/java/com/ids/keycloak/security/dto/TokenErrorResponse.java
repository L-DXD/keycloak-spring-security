package com.ids.keycloak.security.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * 토큰 관련 에러 응답 DTO.
 */
@Getter
@AllArgsConstructor
public class TokenErrorResponse {

    private final String error;

    @JsonProperty("error_description")
    private final String errorDescription;
}
