package com.ids.keycloak.security.sample.e2e;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * 테스트 Keycloak의 관리 API. realm 설정 확인(E2E-03)과 이벤트 세기(JWT-09, REFRESH-02)에 쓴다.
 * <p>
 * 테스트용 Keycloak에만 쓴다. 관리자 계정은 테스트 값이다.
 */
public class KeycloakAdmin {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final E2eEnvironment env;
    private final HttpClient http = HttpClient.newBuilder()
        .proxy(HttpClient.Builder.NO_PROXY)
        .connectTimeout(Duration.ofSeconds(10))
        .build();

    public KeycloakAdmin(E2eEnvironment env) {
        this.env = env;
    }

    /** clientId로 client 설정을 읽는다. */
    public JsonNode client(String clientId) {
        JsonNode clients = getJson("/admin/realms/" + E2eEnvironment.REALM + "/clients?clientId=" + encode(clientId));
        if (clients.size() != 1) {
            throw new AssertionError("client " + clientId + "가 " + clients.size() + "개다");
        }
        return clients.get(0);
    }

    /** realm 설정. */
    public JsonNode realm() {
        return getJson("/admin/realms/" + E2eEnvironment.REALM);
    }

    /** 사용자 이벤트 (최근 것부터). 예: type=REFRESH_TOKEN, client=demo */
    public List<JsonNode> events(String type, String clientId) {
        JsonNode events = getJson("/admin/realms/" + E2eEnvironment.REALM + "/events?max=500&type=" + encode(type) + "&client=" + encode(clientId));
        return events.valueStream().toList();
    }

    /** 사용자 이름 → Keycloak 사용자 id ({@code sub}). */
    public String userId(String username) {
        JsonNode users = getJson("/admin/realms/" + E2eEnvironment.REALM + "/users?exact=true&username=" + encode(username));
        if (users.size() != 1) {
            throw new AssertionError("사용자 " + username + "가 " + users.size() + "명이다");
        }
        return users.get(0).get("id").asString();
    }

    /** OIDC 설명 문서 (관리자 토큰 없이). */
    public JsonNode discovery() {
        return send(HttpRequest.newBuilder(URI.create(env.issuer() + "/.well-known/openid-configuration")).GET().build());
    }

    private JsonNode getJson(String path) {
        return send(HttpRequest.newBuilder(URI.create(env.keycloakUrl() + path))
            .header("Authorization", "Bearer " + adminToken())
            .GET()
            .build());
    }

    private String adminToken() {
        Map<String, String> form = Map.of(
            "grant_type", "password",
            "client_id", "admin-cli",
            "username", env.adminUsername(),
            "password", env.adminPassword());
        String body = form.entrySet().stream().map(e -> e.getKey() + "=" + encode(e.getValue())).collect(Collectors.joining("&"));
        JsonNode token = send(HttpRequest.newBuilder(URI.create(env.keycloakUrl() + "/realms/master/protocol/openid-connect/token"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build());
        return token.get("access_token").asString();
    }

    private JsonNode send(HttpRequest request) {
        try {
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new AssertionError(request.method() + " " + request.uri() + " -> " + response.statusCode() + " " + response.body());
            }
            return JSON.readTree(response.body());
        } catch (IOException e) {
            throw new IllegalStateException(request.uri() + " 실패", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
