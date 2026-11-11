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
 * 테스트 Keycloak의 관리 API. realm 설정 확인(E2E-03), 이벤트 세기(JWT-09, REFRESH-02), 임시 사용자 만들기·막기(REFRESH-04)에 쓴다.
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

    /**
     * {@code since} 뒤에 생긴 사용자 이벤트. 이벤트 저장소에 이전 실행의 이벤트가 쌓여 {@link #events} 개수가 상한(500)에 닿아도
     * 이 테스트 동안의 것만 센다.
     */
    public List<JsonNode> eventsSince(String type, String clientId, java.time.Instant since) {
        JsonNode events = getJson("/admin/realms/" + E2eEnvironment.REALM + "/events?max=1000&type=" + encode(type) + "&client=" + encode(clientId));
        return events.valueStream().filter(e -> e.get("time").asLong() >= since.toEpochMilli()).toList();
    }

    /**
     * Keycloak 세션 하나(kc sid)의 사용자 이벤트. 이벤트 저장소에 이전 실행의 이벤트가 쌓여도 이 로그인 것만 센다.
     * 예: type=REFRESH_TOKEN
     */
    public List<JsonNode> sessionEvents(String type, String keycloakSessionId) {
        JsonNode events = getJson("/admin/realms/" + E2eEnvironment.REALM + "/events?max=1000&type=" + encode(type));
        return events.valueStream().filter(e -> e.has("sessionId") && keycloakSessionId.equals(e.get("sessionId").asString())).toList();
    }

    /** 이 테스트만 쓰는 사용자를 만든다 (프로필 항목을 채워 로그인 때 추가 화면이 나오지 않게). 사용자 id를 돌려준다. */
    public String createUser(String username, String password) {
        String body = """
            {"username":"%s","enabled":true,"email":"%s@users.kss.test","emailVerified":true,"firstName":"Temp","lastName":"User",
             "credentials":[{"type":"password","value":"%s","temporary":false}]}""".formatted(username, username, password);
        call("POST", "/admin/realms/" + E2eEnvironment.REALM + "/users", body, 201);
        return userId(username);
    }

    /** 사용자 계정을 켜거나 끈다. 끈 사용자의 리프레시 토큰은 Keycloak이 invalid_grant로 거절한다. */
    public void setUserEnabled(String userId, boolean enabled) {
        // 사용자 프로필 검사 때문에 일부 항목만 보내지 않고, 읽은 표현 전체에서 enabled만 바꿔 보낸다
        String path = "/admin/realms/" + E2eEnvironment.REALM + "/users/" + userId;
        tools.jackson.databind.node.ObjectNode user = (tools.jackson.databind.node.ObjectNode) getJson(path);
        user.put("enabled", enabled);
        call("PUT", path, JSON.writeValueAsString(user), 204);
    }

    public void deleteUser(String userId) {
        call("DELETE", "/admin/realms/" + E2eEnvironment.REALM + "/users/" + userId, null, 204);
    }

    /** 사용자의 Keycloak 세션 id 목록 (로그아웃하면 그 세션이 빠진다). */
    public List<String> userSessions(String userId) {
        return getJson("/admin/realms/" + E2eEnvironment.REALM + "/users/" + userId + "/sessions").valueStream()
            .map(s -> s.get("id").asString()).toList();
    }

    /** 사용자 이름 → Keycloak 사용자 id ({@code sub}). */
    public String userId(String username) {
        JsonNode users = getJson("/admin/realms/" + E2eEnvironment.REALM + "/users?exact=true&username=" + encode(username));
        if (users.size() != 1) {
            throw new AssertionError("사용자 " + username + "가 " + users.size() + "명이다");
        }
        return users.get(0).get("id").asString();
    }

    /**
     * realm에 RSA 서명 키 제공자를 넣는다(같은 이름이 있으면 지우고 새로). 우선순위를 낮게 주면 Keycloak은 자기 키로 서명하고
     * 이 키는 JWKS에만 나온다. 넣은 키의 kid를 돌려준다.
     */
    public String replaceRsaKey(String name, String privateKeyBase64, int priority) {
        String realm = "/admin/realms/" + E2eEnvironment.REALM;
        String type = "org.keycloak.keys.KeyProvider";
        getJson(realm + "/components?type=" + encode(type) + "&name=" + encode(name)).valueStream()
            .forEach(c -> call("DELETE", realm + "/components/" + c.get("id").asString(), null, 204));
        String body = """
            {"name":"%s","providerId":"rsa","providerType":"%s","parentId":"%s",
             "config":{"priority":["%d"],"enabled":["true"],"active":["true"],"algorithm":["RS256"],"privateKey":["%s"]}}"""
            .formatted(name, type, realm().get("id").asString(), priority, privateKeyBase64);
        call("POST", realm + "/components", body, 201);
        String componentId = getJson(realm + "/components?type=" + encode(type) + "&name=" + encode(name)).get(0).get("id").asString();
        return getJson(realm + "/keys").get("keys").valueStream()
            .filter(k -> componentId.equals(k.path("providerId").asString(""))).findFirst()
            .orElseThrow(() -> new AssertionError("넣은 키가 realm 키 목록에 없다: " + name)).get("kid").asString();
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

    private void call(String method, String path, String json, int expectedStatus) {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(env.keycloakUrl() + path))
            .header("Authorization", "Bearer " + adminToken());
        if (json != null) {
            request.header("Content-Type", "application/json").method(method, HttpRequest.BodyPublishers.ofString(json));
        } else {
            request.method(method, HttpRequest.BodyPublishers.noBody());
        }
        try {
            HttpResponse<String> response = http.send(request.build(), HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != expectedStatus) {
                throw new AssertionError(method + " " + path + " -> " + response.statusCode() + " " + response.body());
            }
        } catch (IOException e) {
            throw new IllegalStateException(path + " 실패", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
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
