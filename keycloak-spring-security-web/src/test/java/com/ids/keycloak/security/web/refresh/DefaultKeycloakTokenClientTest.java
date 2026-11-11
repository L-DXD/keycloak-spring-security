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
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import com.sun.net.httpserver.HttpServer;

/** 기본 토큰 클라이언트를 진짜 HTTP 서버(가짜 Keycloak 토큰 주소)에 붙여 본다. */
class DefaultKeycloakTokenClientTest {

    HttpServer server;
    final AtomicReference<Answer> answer = new AtomicReference<>(new Answer(200,
        "{\"access_token\":\"new-at\",\"token_type\":\"Bearer\",\"expires_in\":60,\"refresh_token\":\"new-rt\",\"refresh_expires_in\":120}"));
    final List<String> requests = new ArrayList<>();
    final AtomicReference<Answer> endpointAnswer = new AtomicReference<>(new Answer(204, ""));

    record Answer(int status, String body) {
    }

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        for (String path : new String[] {"/realms/demo/protocol/openid-connect/logout", "/realms/demo/protocol/openid-connect/revoke",
            "/custom/logout"}) {
            server.createContext(path, exchange -> {
                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                synchronized (requests) {
                    requests.add(exchange.getRequestURI().getPath() + " " + exchange.getRequestHeaders().getFirst("Authorization") + " "
                        + URLDecoder.decode(body, StandardCharsets.UTF_8));
                }
                Answer a = endpointAnswer.get();
                byte[] bytes = a.body().getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(a.status(), a.status() == 204 ? -1 : bytes.length);
                if (a.status() != 204) {
                    try (OutputStream out = exchange.getResponseBody()) {
                        out.write(bytes);
                    }
                }
                exchange.close();
            });
        }
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
        return builder(base).build();
    }

    ClientRegistration.Builder builder(String base) {
        return ClientRegistration.withRegistrationId("keycloak").clientId("demo").clientSecret("demo-secret")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .scope("openid").authorizationUri(base + "/realms/demo/protocol/openid-connect/auth")
            .tokenUri(base + "/realms/demo/protocol/openid-connect/token").issuerUri(base + "/realms/demo");
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

    @Test
    @DisplayName("LOGOUT-01 로그아웃: {issuer}/protocol/openid-connect/logout에 client 인증(Basic)과 refresh_token을 POST, 204면 끝")
    void logout() {
        new DefaultKeycloakTokenClient(registration(base())).logout("rt-1");

        assertThat(requests).singleElement().satisfies(r -> assertThat(r)
            .startsWith("/realms/demo/protocol/openid-connect/logout Basic ")
            .endsWith(" refresh_token=rt-1"));
    }

    @Test
    @DisplayName("LOGOUT-02 Keycloak이 로그아웃을 거절(400 invalid_grant)하면 KeycloakTokenException")
    void logoutRejected() {
        endpointAnswer.set(new Answer(400, "{\"error\":\"invalid_grant\",\"error_description\":\"Session not active\"}"));

        assertThatThrownBy(() -> new DefaultKeycloakTokenClient(registration(base())).logout("rt-1"))
            .isInstanceOfSatisfying(KeycloakTokenException.class, e -> assertThat(e.isInvalidGrant()).isTrue());
    }

    @Test
    @DisplayName("Keycloak에 닿지 않으면 로그아웃도 KeycloakTokenException (temporarily_unavailable)")
    void logoutUnreachable() throws IOException {
        int closedPort;
        try (ServerSocket socket = new ServerSocket(0)) {
            closedPort = socket.getLocalPort();
        }

        assertThatThrownBy(() -> new DefaultKeycloakTokenClient(registration("http://127.0.0.1:" + closedPort)).logout("rt-1"))
            .isInstanceOfSatisfying(KeycloakTokenException.class, e -> assertThat(e.errorCode()).isEqualTo("temporarily_unavailable"));
    }

    @Test
    @DisplayName("LOGOUT-06 폐기: revoke 주소에 token과 token_type_hint=refresh_token을 POST")
    void revoke() {
        endpointAnswer.set(new Answer(200, ""));

        new DefaultKeycloakTokenClient(registration(base())).revoke("rt-1");

        assertThat(requests).singleElement().satisfies(r -> assertThat(r)
            .startsWith("/realms/demo/protocol/openid-connect/revoke Basic ")
            .contains("token=rt-1").contains("token_type_hint=refresh_token"));
    }

    @Test
    @DisplayName("설명 문서에 end_session_endpoint가 있으면 그 주소, client_secret_post면 폼에 client_id·client_secret")
    void metadataEndpointAndClientSecretPost() {
        ClientRegistration registration = builder(base())
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
            .providerConfigurationMetadata(Map.of("end_session_endpoint", base() + "/custom/logout"))
            .build();

        new DefaultKeycloakTokenClient(registration).logout("rt-1");

        assertThat(requests).singleElement().satisfies(r -> assertThat(r)
            .startsWith("/custom/logout null ")
            .contains("client_id=demo").contains("client_secret=demo-secret").contains("refresh_token=rt-1"));
    }
}
