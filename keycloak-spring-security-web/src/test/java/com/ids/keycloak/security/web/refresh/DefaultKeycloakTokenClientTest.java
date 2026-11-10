package com.ids.keycloak.security.web.refresh;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import com.sun.net.httpserver.HttpServer;

/** 기본 토큰 클라이언트를 진짜 HTTP 서버(가짜 Keycloak 토큰 주소)에 붙여 본다. */
class DefaultKeycloakTokenClientTest {

    HttpServer server;
    final AtomicReference<Answer> answer = new AtomicReference<>(new Answer(200,
        "{\"access_token\":\"new-at\",\"token_type\":\"Bearer\",\"expires_in\":60,\"refresh_token\":\"new-rt\",\"refresh_expires_in\":120}"));
    final List<String> requests = new ArrayList<>();

    record Answer(int status, String body) {
    }

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/realms/demo/protocol/openid-connect/token", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            synchronized (requests) {
                requests.add(exchange.getRequestHeaders().getFirst("Authorization") + " " + URLDecoder.decode(body, StandardCharsets.UTF_8));
            }
            Answer a = answer.get();
            byte[] bytes = a.body().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(a.status(), bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    ClientRegistration registration(String base) {
        return ClientRegistration.withRegistrationId("keycloak").clientId("demo").clientSecret("demo-secret")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .scope("openid").authorizationUri(base + "/realms/demo/protocol/openid-connect/auth")
            .tokenUri(base + "/realms/demo/protocol/openid-connect/token").build();
    }

    String base() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @Test
    @DisplayName("refresh_token 요청을 client 인증(Basic)과 함께 보내고, 새 토큰과 리프레시 만료를 읽는다")
    void refreshes() {
        KeycloakTokenResponse response = new DefaultKeycloakTokenClient(registration(base())).refresh("old-rt");

        assertThat(response.accessToken()).isEqualTo("new-at");
        assertThat(response.refreshToken()).isEqualTo("new-rt");
        assertThat(response.refreshExpiresAt()).isBetween(Instant.now().plusSeconds(100), Instant.now().plusSeconds(121));
        assertThat(requests).singleElement().satisfies(r -> assertThat(r)
            .startsWith("Basic ")
            .contains("grant_type=refresh_token")
            .contains("refresh_token=old-rt"));
        assertThat(response.toString()).doesNotContain("new-at").doesNotContain("new-rt");
    }

    @Test
    @DisplayName("Keycloak이 400 invalid_grant면 isInvalidGrant (세션을 끝낼 오류)")
    void invalidGrant() {
        answer.set(new Answer(400, "{\"error\":\"invalid_grant\",\"error_description\":\"Session not active\"}"));

        assertThatThrownBy(() -> new DefaultKeycloakTokenClient(registration(base())).refresh("old-rt"))
            .isInstanceOfSatisfying(KeycloakTokenException.class, e -> assertThat(e.isInvalidGrant()).isTrue());
    }

    @Test
    @DisplayName("Keycloak이 500이면 invalid_grant가 아니다 (세션을 두고 503)")
    void serverError() {
        answer.set(new Answer(500, "{\"error\":\"unknown_error\"}"));

        assertThatThrownBy(() -> new DefaultKeycloakTokenClient(registration(base())).refresh("old-rt"))
            .isInstanceOfSatisfying(KeycloakTokenException.class, e -> assertThat(e.isInvalidGrant()).isFalse());
    }

    @Test
    @DisplayName("client 인증 실패(401 invalid_client)도 invalid_grant가 아니다 (설정 문제로 사용자를 내보내지 않는다)")
    void invalidClient() {
        answer.set(new Answer(401, "{\"error\":\"invalid_client\",\"error_description\":\"Invalid client credentials\"}"));

        assertThatThrownBy(() -> new DefaultKeycloakTokenClient(registration(base())).refresh("old-rt"))
            .isInstanceOfSatisfying(KeycloakTokenException.class, e -> assertThat(e.isInvalidGrant()).isFalse());
    }

    @Test
    @DisplayName("Keycloak에 연결하지 못하면 invalid_grant가 아니다")
    void connectionRefused() throws IOException {
        int closedPort;
        try (ServerSocket socket = new ServerSocket(0)) {
            closedPort = socket.getLocalPort();
        }

        assertThatThrownBy(() -> new DefaultKeycloakTokenClient(registration("http://127.0.0.1:" + closedPort)).refresh("old-rt"))
            .isInstanceOfSatisfying(KeycloakTokenException.class, e -> {
                assertThat(e.isInvalidGrant()).isFalse();
                assertThat(e.errorCode()).isEqualTo("invalid_token_response");
            });
    }
}
