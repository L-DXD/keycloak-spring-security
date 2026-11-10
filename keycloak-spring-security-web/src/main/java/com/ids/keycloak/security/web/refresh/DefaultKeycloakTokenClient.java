package com.ids.keycloak.security.web.refresh;

import java.net.http.HttpClient;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.web.client.RestClient;

/**
 * 기본 토큰 클라이언트: Spring Security OAuth2 Client의 refresh_token 요청을 쓴다(client 인증 방식은 등록 설정대로).
 * 연결 2초·읽기 5초. 프록시는 쓰지 않는다(바꾸려면 {@link RestClient}를 넘기는 생성자).
 */
public class DefaultKeycloakTokenClient implements KeycloakTokenClient {

    private final ClientRegistration registration;
    private final RestClientRefreshTokenTokenResponseClient refreshClient = new RestClientRefreshTokenTokenResponseClient();

    public DefaultKeycloakTokenClient(ClientRegistration registration) {
        this(registration, defaultRestClient(Duration.ofSeconds(2), Duration.ofSeconds(5)));
    }

    /**
     * @param restClient Keycloak을 부를 클라이언트. 폼 변환기, {@link OAuth2AccessTokenResponseHttpMessageConverter},
     *                   {@link OAuth2ErrorResponseErrorHandler}가 있어야 한다({@link #defaultRestClient} 참고)
     */
    public DefaultKeycloakTokenClient(ClientRegistration registration, RestClient restClient) {
        this.registration = Objects.requireNonNull(registration);
        this.refreshClient.setRestClient(Objects.requireNonNull(restClient));
    }

    /** 기본 클라이언트 (연결·읽기 타임아웃, 프록시 없음). */
    public static RestClient defaultRestClient(Duration connectTimeout, Duration readTimeout) {
        HttpClient http = HttpClient.newBuilder().connectTimeout(connectTimeout).followRedirects(HttpClient.Redirect.NEVER).build();
        JdkClientHttpRequestFactory requestFactory = new JdkClientHttpRequestFactory(http);
        requestFactory.setReadTimeout(readTimeout);
        return RestClient.builder()
            .requestFactory(requestFactory)
            .configureMessageConverters(converters -> {
                converters.addCustomConverter(new FormHttpMessageConverter());
                converters.addCustomConverter(new OAuth2AccessTokenResponseHttpMessageConverter());
            })
            .defaultStatusHandler(new OAuth2ErrorResponseErrorHandler())
            .build();
    }

    @Override
    public KeycloakTokenResponse refresh(String refreshToken) {
        OAuth2AccessTokenResponse response;
        try {
            response = refreshClient.getTokenResponse(new OAuth2RefreshTokenGrantRequest(registration, placeholderAccessToken(),
                new OAuth2RefreshToken(refreshToken, null)));
        } catch (OAuth2AuthorizationException e) {
            throw new KeycloakTokenException(e.getError().getErrorCode(), "Keycloak 갱신 실패: " + e.getError(), e);
        }
        OAuth2RefreshToken newRefreshToken = response.getRefreshToken();
        return new KeycloakTokenResponse(response.getAccessToken().getTokenValue(),
            newRefreshToken == null ? null : newRefreshToken.getTokenValue(), refreshExpiresAt(response));
    }

    /**
     * Spring 요청 객체가 예전 액세스 토큰을 받게 되어 있지만, 응답에 scope가 없을 때 채우는 데만 쓴다.
     * at 쿠키가 이미 없을 수 있으므로 등록 scope만 가진 자리 표시자를 넣는다.
     */
    private OAuth2AccessToken placeholderAccessToken() {
        Instant now = Instant.now();
        return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "unused", now.minusSeconds(1), now, registration.getScopes());
    }

    private static Instant refreshExpiresAt(OAuth2AccessTokenResponse response) {
        Object seconds = response.getAdditionalParameters().get("refresh_expires_in");
        if (seconds instanceof Number number && number.longValue() > 0) {
            return Instant.now().plusSeconds(number.longValue());
        }
        if (seconds instanceof String text && text.matches("\\d+")) {
            return Instant.now().plusSeconds(Long.parseLong(text));
        }
        return null;
    }

    @Override
    public String toString() {
        return "DefaultKeycloakTokenClient[" + registration.getProviderDetails().getTokenUri() + "]";
    }
}
