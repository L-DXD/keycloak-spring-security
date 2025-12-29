package com.ids.keycloak.security.test.servlet;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    classes = ServletApp.class
)
class AutoConfigurationIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void whenUnauthenticated_thenReturns200OkWithCustomSecurityFilterChain() {
        // when
        ResponseEntity<String> response = restTemplate.getForEntity("/test", String.class);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }
}
