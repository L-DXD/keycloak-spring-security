package com.ids.keycloak.security.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import com.sd.KeycloakClient.client.auth.async.KeycloakAuthAsyncClient;
import com.sd.KeycloakClient.dto.KeycloakResponse;
import com.sd.KeycloakClient.dto.auth.KeycloakTokenInfo;
import com.sd.KeycloakClient.factory.KeycloakClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

/**
 * M-N1: {@link KeycloakReactiveTokenController} 단위 테스트.
 *
 * <p>{@code WebTestClient.bindToController}로 컨트롤러를 직접 바인딩하여
 * 검증 실패 시 OAuth2 표준 에러 포맷({@code error/error_description}) + 400 응답을 확인합니다.</p>
 */
@ExtendWith(MockitoExtension.class)
class KeycloakReactiveTokenControllerTest {

  @Mock
  private KeycloakClient keycloakClient;

  @Mock
  private KeycloakAuthAsyncClient authAsyncClient;

  private WebTestClient webTestClient;

  @BeforeEach
  void setUp() {
    lenient().when(keycloakClient.authAsync()).thenReturn(authAsyncClient);
    KeycloakReactiveTokenController controller =
        new KeycloakReactiveTokenController(keycloakClient, "/auth");

    webTestClient = WebTestClient
        .bindToController(controller)
        .build();
  }

  // ===========================================================================
  // M-N1: @Valid 위반 → 400 + OAuth2 표준 에러 포맷 검증
  // ===========================================================================

  @Nested
  @DisplayName("M-N1: @Valid 위반 시 OAuth2 표준 에러 포맷(400) 반환")
  class 유효성검증_실패 {

    @Test
    @DisplayName("username 빈 값 → 400 + error=invalid_request 포함")
    void username_빈값_400_invalid_request() {
      String body = webTestClient.post()
          .uri("/auth/token")
          .contentType(MediaType.APPLICATION_JSON)
          .bodyValue("{\"username\":\"\",\"password\":\"secret\"}")
          .exchange()
          .expectStatus().isBadRequest()
          .expectBody(String.class)
          .returnResult()
          .getResponseBody();

      assertThat(body).contains("invalid_request");
      assertThat(body).contains("error_description");
      // Spring 기본 에러 포맷 키 없음 확인
      assertThat(body).doesNotContain("\"timestamp\"");
      assertThat(body).doesNotContain("\"status\"");
    }

    @Test
    @DisplayName("password 빈 값 → 400 + error=invalid_request 포함")
    void password_빈값_400_invalid_request() {
      String body = webTestClient.post()
          .uri("/auth/token")
          .contentType(MediaType.APPLICATION_JSON)
          .bodyValue("{\"username\":\"user1\",\"password\":\"\"}")
          .exchange()
          .expectStatus().isBadRequest()
          .expectBody(String.class)
          .returnResult()
          .getResponseBody();

      assertThat(body).contains("invalid_request");
      assertThat(body).contains("error_description");
    }

    @Test
    @DisplayName("username과 password 모두 빈 값 → 400 + error=invalid_request 포함")
    void 모두_빈값_400_invalid_request() {
      String body = webTestClient.post()
          .uri("/auth/token")
          .contentType(MediaType.APPLICATION_JSON)
          .bodyValue("{\"username\":\"\",\"password\":\"\"}")
          .exchange()
          .expectStatus().isBadRequest()
          .expectBody(String.class)
          .returnResult()
          .getResponseBody();

      assertThat(body).contains("invalid_request");
      assertThat(body).contains("error_description");
    }

    @Test
    @DisplayName("Spring 기본 에러 포맷(timestamp/status) 키 없음 확인")
    void spring_기본_에러_포맷_없음() {
      String body = webTestClient.post()
          .uri("/auth/token")
          .contentType(MediaType.APPLICATION_JSON)
          .bodyValue("{\"username\":\"\",\"password\":\"secret\"}")
          .exchange()
          .expectStatus().isBadRequest()
          .expectBody(String.class)
          .returnResult()
          .getResponseBody();

      assertThat(body).doesNotContain("\"timestamp\"");
      assertThat(body).doesNotContain("\"status\"");
      assertThat(body).contains("\"error\"");
    }
  }

  // ===========================================================================
  // 정상 경로: 기존 동작 회귀 없음 확인
  // ===========================================================================

  @Nested
  @DisplayName("정상 경로: 기존 동작 회귀 없음")
  class 정상_경로 {

    @Test
    @DisplayName("유효한 요청 → Keycloak 호출 후 200 + access_token 포함 응답")
    void 유효한_요청_200() {
      KeycloakTokenInfo tokenInfo = KeycloakTokenInfo.builder()
          .accessToken("access-token-value")
          .refreshToken("refresh-token-value")
          .idToken("id-token-value")
          .expireTime(300)
          .build();

      KeycloakResponse<KeycloakTokenInfo> response =
          KeycloakResponse.<KeycloakTokenInfo>builder()
              .status(200)
              .body(tokenInfo)
              .build();

      when(authAsyncClient.basicAuth(anyString(), anyString()))
          .thenReturn(Mono.just(response));

      String body = webTestClient.post()
          .uri("/auth/token")
          .contentType(MediaType.APPLICATION_JSON)
          .bodyValue("{\"username\":\"user1\",\"password\":\"secret\"}")
          .exchange()
          .expectStatus().isOk()
          .expectBody(String.class)
          .returnResult()
          .getResponseBody();

      assertThat(body).contains("access-token-value");
      assertThat(body).contains("Bearer");
    }
  }
}
