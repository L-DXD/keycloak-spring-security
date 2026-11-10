package com.ids.keycloak.security.web.cors;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.ids.keycloak.security.web.csrf.SignedDoubleSubmitCsrfTokenRepository;

/**
 * 기본 CORS (V3-10, CORS-01·02): 화면 origin 하나만, 쿠키 허용. {@code *}나 받은 Origin을 그대로 돌려주지 않는다.
 * 보안 체인 맨 앞의 {@code CorsFilter}가 쓰고, Origin 확인({@code KeycloakOriginFilter})도 같은 허용 목록을 쓴다.
 * <p>
 * origin이나 헤더를 더하려면 이 설정으로 만든 {@link CorsConfigurationSource}를 이름 {@code keycloakCorsConfigurationSource}로 올린다.
 * <pre>
 * &#64;Bean
 * CorsConfigurationSource keycloakCorsConfigurationSource(KeycloakSecuritySettings settings) {
 *     CorsConfiguration cors = KeycloakCors.configuration(settings.frontendOrigin(), settings.backgroundHeader());
 *     cors.addAllowedOrigin("https://admin.example.com");
 *     cors.addAllowedHeader("X-Trace-Id");
 *     return KeycloakCors.source(cors);
 * }
 * </pre>
 */
public class KeycloakCors {

    /** 사전 확인 결과를 브라우저가 기억하는 시간. */
    public static final Duration MAX_AGE = Duration.ofMinutes(30);

    private KeycloakCors() {
    }

    /**
     * @param frontendOrigin   화면 origin ({@code scheme://host[:port]})
     * @param backgroundHeader 갱신하지 않을 요청에 붙이는 헤더 (허용 헤더에 넣는다)
     */
    public static CorsConfiguration configuration(String frontendOrigin, String backgroundHeader) {
        CorsConfiguration cors = new CorsConfiguration();
        cors.setAllowedOrigins(new ArrayList<>(List.of(Objects.requireNonNull(frontendOrigin))));
        cors.setAllowCredentials(true);
        cors.setAllowedMethods(new ArrayList<>(List.of("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE")));
        cors.setAllowedHeaders(new ArrayList<>(List.of("Content-Type", "Accept", "X-Requested-With",
            SignedDoubleSubmitCsrfTokenRepository.HEADER_NAME, Objects.requireNonNull(backgroundHeader))));
        cors.setMaxAge(MAX_AGE);
        return cors;
    }

    /** 모든 경로에 같은 설정. */
    public static CorsConfigurationSource source(CorsConfiguration configuration) {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
