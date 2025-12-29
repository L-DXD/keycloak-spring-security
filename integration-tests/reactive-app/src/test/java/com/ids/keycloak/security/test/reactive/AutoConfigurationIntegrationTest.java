package com.ids.keycloak.security.test.reactive;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    classes = ReactiveApp.class
)
class AutoConfigurationIntegrationTest {

    @Autowired
    private WebTestClient webTestClient;

    @Test
    void whenUnauthenticated_thenReturns401WithCustomBody() {
        webTestClient.get().uri("/test")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody()
                .jsonPath("$.code").isEqualTo("AUTHENTICATION_REQUIRED")
                .jsonPath("$.message").isEqualTo("이 리소스에 접근하려면 완전한 인증이 필요합니다.");
    }
}
