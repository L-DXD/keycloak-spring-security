package com.ids.keycloak.security.controller;

import com.ids.keycloak.security.dto.LogoutRequest;
import com.ids.keycloak.security.dto.RefreshRequest;
import com.ids.keycloak.security.dto.TokenErrorResponse;
import com.ids.keycloak.security.dto.TokenRequest;
import com.ids.keycloak.security.dto.TokenResponse;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

/**
 * Bearer Token 발급/갱신/로그아웃 REST 컨트롤러입니다.
 * <p>
 * 패턴 C (Keycloak 프록시): 클라이언트가 Keycloak URL/client 정보를 알 필요 없이
 * 이 컨트롤러를 통해 토큰 관련 작업을 수행합니다.
 * </p>
 * <p>
 * 완전히 Stateless로 동작하며, 서버에 아무런 상태도 저장하지 않습니다.
 * </p>
 */
@RestController
@Slf4j
public class KeycloakTokenController {

    private final String tokenEndpoint;
    private final String logoutEndpoint;
    private final String clientId;
    private final String clientSecret;
    private final String prefix;
    private final RestTemplate restTemplate;

    public KeycloakTokenController(
        String tokenEndpoint,
        String logoutEndpoint,
        String clientId,
        String clientSecret,
        String prefix
    ) {
        this.tokenEndpoint = tokenEndpoint;
        this.logoutEndpoint = logoutEndpoint;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.prefix = prefix;
        this.restTemplate = new RestTemplate();
    }

    /**
     * 토큰 발급: username/password로 Keycloak에 토큰을 요청합니다.
     * grant_type=password
     */
    @PostMapping("${keycloak.security.bearer-token.token-endpoint.prefix:/auth}/token")
    public ResponseEntity<?> issueToken(@RequestBody TokenRequest request) {
        log.debug("[TokenAPI] 토큰 발급 요청: username={}", request.getUsername());

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "password");
        formData.add("client_id", clientId);
        formData.add("client_secret", clientSecret);
        formData.add("username", request.getUsername());
        formData.add("password", request.getPassword());

        return executeTokenRequest(formData);
    }

    /**
     * 토큰 갱신: refresh_token으로 새 access_token을 발급받습니다.
     * grant_type=refresh_token
     */
    @PostMapping("${keycloak.security.bearer-token.token-endpoint.prefix:/auth}/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshRequest request) {
        log.debug("[TokenAPI] 토큰 갱신 요청.");

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "refresh_token");
        formData.add("client_id", clientId);
        formData.add("client_secret", clientSecret);
        formData.add("refresh_token", request.getRefreshToken());

        return executeTokenRequest(formData);
    }

    /**
     * 로그아웃: refresh_token을 Keycloak에서 폐기합니다.
     */
    @PostMapping("${keycloak.security.bearer-token.token-endpoint.prefix:/auth}/logout")
    public ResponseEntity<?> logout(@RequestBody LogoutRequest request) {
        log.debug("[TokenAPI] 로그아웃 요청.");

        try {
            MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
            formData.add("client_id", clientId);
            formData.add("client_secret", clientSecret);
            formData.add("refresh_token", request.getRefreshToken());

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(formData, headers);
            restTemplate.postForEntity(logoutEndpoint, httpEntity, Void.class);

            log.debug("[TokenAPI] 로그아웃 성공.");
            return ResponseEntity.noContent().build();

        } catch (HttpClientErrorException e) {
            log.warn("[TokenAPI] 로그아웃 실패: {}", e.getStatusCode());
            return ResponseEntity.status(e.getStatusCode())
                .body(new TokenErrorResponse("invalid_grant", "Token is not active"));
        } catch (RestClientException e) {
            log.error("[TokenAPI] Keycloak 통신 오류: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new TokenErrorResponse("server_error", "Failed to communicate with authentication server"));
        }
    }

    /**
     * Keycloak token endpoint에 요청을 보내고 응답을 TokenResponse로 변환합니다.
     */
    @SuppressWarnings("unchecked")
    private ResponseEntity<?> executeTokenRequest(MultiValueMap<String, String> formData) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(formData, headers);
            ResponseEntity<Map> response = restTemplate.postForEntity(tokenEndpoint, httpEntity, Map.class);

            Map<String, Object> body = response.getBody();
            if (body == null) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new TokenErrorResponse("server_error", "Empty response from authentication server"));
            }

            TokenResponse tokenResponse = TokenResponse.builder()
                .accessToken((String) body.get("access_token"))
                .refreshToken((String) body.get("refresh_token"))
                .tokenType((String) body.get("token_type"))
                .expiresIn((Integer) body.get("expires_in"))
                .refreshExpiresIn((Integer) body.get("refresh_expires_in"))
                .build();

            log.debug("[TokenAPI] 토큰 요청 성공.");
            return ResponseEntity.ok(tokenResponse);

        } catch (HttpClientErrorException e) {
            log.warn("[TokenAPI] 토큰 요청 실패: {}", e.getStatusCode());
            return ResponseEntity.status(e.getStatusCode())
                .body(new TokenErrorResponse("invalid_grant", "Invalid user credentials"));
        } catch (RestClientException e) {
            log.error("[TokenAPI] Keycloak 통신 오류: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new TokenErrorResponse("server_error", "Failed to communicate with authentication server"));
        }
    }
}
