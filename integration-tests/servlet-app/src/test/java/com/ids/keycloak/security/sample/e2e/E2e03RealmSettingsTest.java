package com.ids.keycloak.security.sample.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import tools.jackson.databind.JsonNode;

/**
 * E2E-03: realm 파일(integration-tests/keycloak/realm-kss-demo.json)이 docs/v3/03-검증-환경.md 3절대로 들어갔다.
 */
@E2eTest
class E2e03RealmSettingsTest {

    private final KeycloakAdmin admin = new KeycloakAdmin(E2eEnvironment.get());

    @ParameterizedTest(name = "E2E-03 client {0}: 비공개, Standard flow만, PKCE S256, redirect 하나, back-channel, Idle 2분/Max 3분, audience, Full scope 끔")
    @CsvSource({"demo, 8443", "demo2, 8444"})
    void clientIsConfiguredAsDocumented(String clientId, int port) {
        JsonNode client = admin.client(clientId);
        JsonNode attributes = client.get("attributes");
        String api = "https://api.kss.test:" + port;

        assertThat(client.get("publicClient").asBoolean()).as("비공개 client").isFalse();
        assertThat(client.get("standardFlowEnabled").asBoolean()).as("Standard flow").isTrue();
        assertThat(client.get("implicitFlowEnabled").asBoolean()).as("Implicit").isFalse();
        assertThat(client.get("directAccessGrantsEnabled").asBoolean()).as("Direct access grants").isFalse();
        assertThat(client.get("serviceAccountsEnabled").asBoolean()).as("Service accounts").isFalse();
        assertThat(attributes.get("pkce.code.challenge.method").asString()).isEqualTo("S256");
        assertThat(client.get("redirectUris").valueStream().map(JsonNode::asString))
            .containsExactly(api + "/login/oauth2/code/keycloak");
        assertThat(attributes.get("post.logout.redirect.uris").asString()).isEqualTo("https://app.kss.test/logged-out");
        assertThat(attributes.get("backchannel.logout.url").asString()).isEqualTo(api + "/logout/connect/back-channel/keycloak");
        assertThat(attributes.get("backchannel.logout.session.required").asString()).isEqualTo("true");
        assertThat(attributes.get("client.session.idle.timeout").asString()).isEqualTo("120");
        assertThat(attributes.get("client.session.max.lifespan").asString()).isEqualTo("180");
        assertThat(client.get("fullScopeAllowed").asBoolean()).as("Full scope").isFalse();
        assertThat(client.get("protocolMappers").valueStream()
            .filter(m -> m.get("protocolMapper").asString().equals("oidc-audience-mapper"))
            .map(m -> m.get("config").get("included.client.audience").asString()))
            .containsExactly(clientId);
    }

    @ParameterizedTest(name = "E2E-03 realm: 액세스 토큰 60초, 사용자 이벤트 저장 켬")
    @CsvSource({"kss-demo"})
    void realmIsConfiguredForTests(String realmName) {
        JsonNode realm = admin.realm();

        assertThat(realm.get("realm").asString()).isEqualTo(realmName);
        assertThat(realm.get("accessTokenLifespan").asInt()).isEqualTo(60);
        assertThat(realm.get("eventsEnabled").asBoolean()).isTrue();
        assertThat(realm.get("enabledEventTypes").valueStream().map(JsonNode::asString))
            .contains("LOGIN", "CODE_TO_TOKEN", "REFRESH_TOKEN", "LOGOUT");
    }
}
