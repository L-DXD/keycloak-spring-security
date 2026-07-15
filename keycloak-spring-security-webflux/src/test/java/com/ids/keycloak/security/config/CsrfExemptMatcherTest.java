package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.authentication.KeycloakReactiveAuthenticationManager;
import com.ids.keycloak.security.filter.ReactiveBackChannelLogoutEndpointFilter;
import com.ids.keycloak.security.session.ReactiveSessionManager;
import com.ids.keycloak.security.web.reactive.KeycloakServerAccessDeniedHandler;
import com.ids.keycloak.security.web.reactive.KeycloakServerAuthenticationEntryPoint;
import com.sd.KeycloakClient.factory.KeycloakClient;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.csrf.CsrfWebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.test.StepVerifier;

/**
 * CSRF 설정 통합 테스트.
 *
 * <p>인라인으로 matcher 로직을 재현하지 않고, {@link KeycloakWebFluxSecurityConfigurer#configure}를
 * 실제로 호출해 만들어진 {@link SecurityWebFilterChain}에서 실제 {@link CsrfWebFilter} 인스턴스를
 * 꺼내 요청을 직접 흘려보내며 검증한다. production {@code configureCsrf}가 조립한 matcher를
 * 그대로 실행하므로, matcher 로직이 바뀌면 이 테스트가 즉시 반응한다.</p>
 *
 * <p>CSRF 보호 = AND(안전하지 않은 메서드, NOT(면제 대상)) 공식 검증:
 * <ul>
 *   <li>면제 경로(Back-Channel 로그아웃/Bearer Token 엔드포인트(전용 로그아웃 포함)/사용자 지정
 *   ignore-paths) → CSRF 토큰 없이도 통과</li>
 *   <li>일반 경로 + 안전하지 않은 메서드(POST/PUT/PATCH/DELETE) → CSRF 토큰이 없으면 403</li>
 *   <li><b>보안 Medium 3:</b> 안전 메서드(GET/HEAD/OPTIONS)는 {@link CsrfWebFilter#DEFAULT_CSRF_MATCHER}에
 *   의해 비면제 경로에서도 CSRF 토큰 없이 항상 통과해야 한다 — 그렇지 않으면 일반 GET, OIDC 로그인
 *   콜백, 정적 리소스, 리다이렉트 등이 403으로 차단된다.</li>
 *   <li><b>보안 Medium 4:</b> 브라우저 Front-Channel 로그아웃({@code /logout})은 Bearer Token
 *   전용 로그아웃(prefix + {@code /logout})과 별개 엔드포인트이며, Bearer Token 활성 여부와
 *   무관하게 항상 CSRF 보호를 유지해야 한다(CWE-352 — 강제 로그아웃 CSRF 방지).</li>
 *   <li><b>보안 Advisory 3:</b> {@code Authorization: Basic} 헤더 보유 여부는 더 이상 CSRF 면제
 *   사유가 아니다. Basic 헤더가 있어도 non-ignore 경로에서는 CSRF 토큰이 없으면 403이 반환되어야
 *   한다 — 브라우저가 캐시한 Basic 자격증명(ambient credential)을 이용한 cross-site 폼 제출이
 *   CSRF 검증을 우회하는 것을 막기 위함이다(CWE-352).</li>
 * </ul>
 * </p>
 */
class CsrfExemptMatcherTest {

  // ==========================================================================
  // 헬퍼: production configure()를 실제로 호출해 SecurityWebFilterChain을 빌드하고,
  // 그 안에서 실제 CsrfWebFilter 인스턴스를 꺼낸다 (matcher 로직 복제 없음).
  // ==========================================================================

  private KeycloakSecurityProperties baseProperties() {
    KeycloakSecurityProperties props = new KeycloakSecurityProperties();
    props.getCsrf().setEnabled(true);
    props.getBasicAuth().setEnabled(true);
    return props;
  }

  private CsrfWebFilter buildRealCsrfFilter(KeycloakSecurityProperties props) throws Exception {
    KeycloakClient keycloakClient = mock(KeycloakClient.class);
    ReactiveJwtDecoder jwtDecoder = mock(ReactiveJwtDecoder.class);
    KeycloakReactiveAuthenticationManager authenticationManager =
        new KeycloakReactiveAuthenticationManager(keycloakClient, "test-client", jwtDecoder);
    KeycloakServerAuthenticationEntryPoint entryPoint =
        new KeycloakServerAuthenticationEntryPoint(new ObjectMapper());
    KeycloakServerAccessDeniedHandler accessDeniedHandler =
        new KeycloakServerAccessDeniedHandler(new ObjectMapper());
    ReactiveSessionManager sessionManager = new ReactiveSessionManager();

    SecurityWebFilterChain chain = KeycloakWebFluxSecurityConfigurer.configure(
        ServerHttpSecurity.http(),
        authenticationManager,
        entryPoint,
        accessDeniedHandler,
        props,
        keycloakClient,
        "test-client",
        sessionManager,
        null,   // rateLimiter
        null,   // loggingFilter
        null,   // authLoggingFilter
        null,   // clientRegistrationRepo
        null,   // authorizedClientService
        null,   // backChannelFilter
        null);  // authorizationRequestResolver

    return chain.getWebFilters()
        .filter(CsrfWebFilter.class::isInstance)
        .cast(CsrfWebFilter.class)
        .blockFirst();
  }

  private MockServerWebExchange exchange(String method, String path) {
    MockServerHttpRequest request = MockServerHttpRequest
        .method(HttpMethod.valueOf(method), path).build();
    return MockServerWebExchange.from(request);
  }

  private MockServerWebExchange exchangeWithHeader(String method, String path, String headerName,
      String headerValue) {
    MockServerHttpRequest request = MockServerHttpRequest
        .method(HttpMethod.valueOf(method), path)
        .header(headerName, headerValue).build();
    return MockServerWebExchange.from(request);
  }

  /**
   * 실제 {@link CsrfWebFilter} 인스턴스에 요청을 흘려보내고, 하위 체인까지 도달했는지 여부를 반환한다.
   * CSRF에 막히면 filter가 직접 403을 쓰고 완료하므로 하위 체인(terminal)에 도달하지 못한다.
   */
  private boolean runThroughRealFilter(CsrfWebFilter filter, MockServerWebExchange exchange) {
    AtomicBoolean reachedDownstream = new AtomicBoolean(false);
    WebFilterChain terminal = ex -> {
      reachedDownstream.set(true);
      return ex.getResponse().setComplete();
    };

    StepVerifier.create(filter.filter(exchange, terminal)).verifyComplete();
    return reachedDownstream.get();
  }

  // ==========================================================================
  // 보안 Medium 3: 안전 메서드(GET/HEAD/OPTIONS)는 비면제 경로에서도 CSRF 보호 대상이 아니다.
  // CsrfWebFilter.DEFAULT_CSRF_MATCHER가 안전 메서드를 판정하므로, production configureCsrf가
  // 만든 실제 매처를 태워 검증한다.
  // ==========================================================================

  @Nested
  class 안전_메서드는_비면제_경로에서도_CSRF_보호_대상_아님 {

    @Test
    void GET_요청은_비면제_경로에서도_토큰_없이_통과() throws Exception {
      CsrfWebFilter csrfFilter = buildRealCsrfFilter(baseProperties());

      MockServerWebExchange ex = exchange("GET", "/api/resource");

      assertThat(runThroughRealFilter(csrfFilter, ex)).isTrue();
    }

    @Test
    void HEAD_요청은_비면제_경로에서도_토큰_없이_통과() throws Exception {
      CsrfWebFilter csrfFilter = buildRealCsrfFilter(baseProperties());

      MockServerWebExchange ex = exchange("HEAD", "/api/resource");

      assertThat(runThroughRealFilter(csrfFilter, ex)).isTrue();
    }

    @Test
    void OPTIONS_요청은_비면제_경로에서도_토큰_없이_통과() throws Exception {
      CsrfWebFilter csrfFilter = buildRealCsrfFilter(baseProperties());

      MockServerWebExchange ex = exchange("OPTIONS", "/api/resource");

      assertThat(runThroughRealFilter(csrfFilter, ex)).isTrue();
    }

    @Test
    void OIDC_로그인_콜백_GET_요청은_토큰_없이_통과() throws Exception {
      // OIDC Authorization Code Grant 리다이렉트 콜백. 브라우저가 인가서버에서 리다이렉트되며
      // GET으로 도달하므로 CSRF 토큰을 들고 올 수 없다 — 안전 메서드 예외가 없으면 항상 403이 된다.
      CsrfWebFilter csrfFilter = buildRealCsrfFilter(baseProperties());

      MockServerWebExchange ex = exchange("GET", "/login/oauth2/code/keycloak");

      assertThat(runThroughRealFilter(csrfFilter, ex)).isTrue();
    }
  }

  // ==========================================================================
  // 면제 경로 → CSRF 토큰 없이 통과
  // ==========================================================================

  @Nested
  class 면제_경로_CSRF_보호_없음 {

    @Test
    void BackChannel_로그아웃_경로는_토큰_없이_통과() throws Exception {
      CsrfWebFilter csrfFilter = buildRealCsrfFilter(baseProperties());

      MockServerWebExchange ex = exchange("POST",
          ReactiveBackChannelLogoutEndpointFilter.BACK_CHANNEL_LOGOUT_PATH);

      assertThat(runThroughRealFilter(csrfFilter, ex)).isTrue();
    }

    @Test
    void Bearer_Token_엔드포인트는_토큰_없이_통과() throws Exception {
      KeycloakSecurityProperties props = baseProperties();
      props.getBearerToken().setEnabled(true);
      CsrfWebFilter csrfFilter = buildRealCsrfFilter(props);

      assertThat(runThroughRealFilter(csrfFilter, exchange("POST", "/auth/token"))).isTrue();
      assertThat(runThroughRealFilter(csrfFilter, exchange("POST", "/auth/refresh"))).isTrue();
    }

    @Test
    void 사용자_지정_ignorePaths는_토큰_없이_통과() throws Exception {
      KeycloakSecurityProperties props = baseProperties();
      props.getCsrf().setIgnorePaths(List.of("/webhook/**"));
      CsrfWebFilter csrfFilter = buildRealCsrfFilter(props);

      assertThat(runThroughRealFilter(csrfFilter, exchange("POST", "/webhook/event"))).isTrue();
    }
  }

  // ==========================================================================
  // 일반 경로 → CSRF 토큰이 없으면 403
  // ==========================================================================

  @Nested
  class 일반_경로_CSRF_보호_적용 {

    @Test
    void 일반_API_경로는_토큰_없으면_403() throws Exception {
      CsrfWebFilter csrfFilter = buildRealCsrfFilter(baseProperties());

      MockServerWebExchange ex = exchange("POST", "/api/submit");
      boolean reached = runThroughRealFilter(csrfFilter, ex);

      assertThat(reached).isFalse();
      assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void 루트_경로는_토큰_없으면_403() throws Exception {
      CsrfWebFilter csrfFilter = buildRealCsrfFilter(baseProperties());

      MockServerWebExchange ex = exchange("POST", "/");
      boolean reached = runThroughRealFilter(csrfFilter, ex);

      assertThat(reached).isFalse();
      assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void PUT_요청은_비면제_경로에서_토큰_없으면_403() throws Exception {
      CsrfWebFilter csrfFilter = buildRealCsrfFilter(baseProperties());

      MockServerWebExchange ex = exchange("PUT", "/api/resource");
      boolean reached = runThroughRealFilter(csrfFilter, ex);

      assertThat(reached).isFalse();
      assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void PATCH_요청은_비면제_경로에서_토큰_없으면_403() throws Exception {
      CsrfWebFilter csrfFilter = buildRealCsrfFilter(baseProperties());

      MockServerWebExchange ex = exchange("PATCH", "/api/resource");
      boolean reached = runThroughRealFilter(csrfFilter, ex);

      assertThat(reached).isFalse();
      assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void DELETE_요청은_비면제_경로에서_토큰_없으면_403() throws Exception {
      CsrfWebFilter csrfFilter = buildRealCsrfFilter(baseProperties());

      MockServerWebExchange ex = exchange("DELETE", "/api/resource");
      boolean reached = runThroughRealFilter(csrfFilter, ex);

      assertThat(reached).isFalse();
      assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }
  }

  // ==========================================================================
  // 보안 Medium #4: 브라우저 Front-Channel 로그아웃(/logout)은 Bearer Token 활성 여부와
  // 무관하게 항상 CSRF 보호를 유지한다. Bearer Token 전용 로그아웃(prefix + "/logout")과는
  // 별개의 엔드포인트이며, 과거처럼 Bearer 활성 시 /logout까지 면제하면 공격 사이트가
  // 크로스사이트 POST로 로그인 사용자를 강제 로그아웃시킬 수 있다(CWE-352).
  // ==========================================================================

  @Nested
  class Medium4_브라우저_logout_CSRF_보호_항상_유지 {

    @Test
    void bearerToken_비활성시_logout_경로는_CSRF_보호_적용됨() throws Exception {
      CsrfWebFilter csrfFilter = buildRealCsrfFilter(baseProperties());

      MockServerWebExchange ex = exchange("POST", "/logout");
      boolean reached = runThroughRealFilter(csrfFilter, ex);

      assertThat(reached).isFalse();
      assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void bearerToken_활성시에도_logout_경로는_CSRF_보호_유지() throws Exception {
      // 보안 Medium #4 회귀 방지: Bearer Token을 켜도 브라우저 /logout은 면제되면 안 된다.
      KeycloakSecurityProperties props = baseProperties();
      props.getBearerToken().setEnabled(true);
      CsrfWebFilter csrfFilter = buildRealCsrfFilter(props);

      MockServerWebExchange ex = exchange("POST", "/logout");
      boolean reached = runThroughRealFilter(csrfFilter, ex);

      assertThat(reached).isFalse();
      assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void bearerToken_활성시_전용_logout_엔드포인트는_CSRF_면제() throws Exception {
      // Bearer 전용 로그아웃(prefix + "/logout")은 브라우저 폼 세션과 무관하므로 계속 면제된다.
      KeycloakSecurityProperties props = baseProperties();
      props.getBearerToken().setEnabled(true);
      CsrfWebFilter csrfFilter = buildRealCsrfFilter(props);

      String prefix = props.getBearerToken().getTokenEndpoint().getPrefix();
      assertThat(runThroughRealFilter(csrfFilter, exchange("POST", prefix + "/logout"))).isTrue();
    }

    @Test
    void bearerToken_비활성시_back_channel_경로는_여전히_CSRF_면제() throws Exception {
      CsrfWebFilter csrfFilter = buildRealCsrfFilter(baseProperties());

      MockServerWebExchange ex = exchange("POST",
          ReactiveBackChannelLogoutEndpointFilter.BACK_CHANNEL_LOGOUT_PATH);

      assertThat(runThroughRealFilter(csrfFilter, ex)).isTrue();
    }
  }

  // ==========================================================================
  // 보안 Advisory 3: Authorization: Basic 헤더는 더 이상 CSRF 면제 사유가 아니다.
  // ==========================================================================

  @Nested
  class BasicAuth_헤더는_더이상_CSRF_면제_아님 {

    @Test
    void Authorization_Basic_헤더가_있어도_non_ignore_경로는_403() throws Exception {
      CsrfWebFilter csrfFilter = buildRealCsrfFilter(baseProperties());

      MockServerWebExchange ex = exchangeWithHeader("POST", "/api/resource",
          "Authorization", "Basic dXNlcjpwYXNz");
      boolean reached = runThroughRealFilter(csrfFilter, ex);

      assertThat(reached)
          .as("Basic 헤더 보유만으로 CSRF가 면제되면 안 된다 (Advisory 3)")
          .isFalse();
      assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void Authorization_Basic_헤더_브라우저성_cross_site_요청도_403() throws Exception {
      // ambient credential 재전송 시나리오: 브라우저가 캐시한 Basic 자격증명을 실은 채
      // 공격자 origin에서 만든 폼이 자동 제출되는 상황을 흉내낸다.
      CsrfWebFilter csrfFilter = buildRealCsrfFilter(baseProperties());

      MockServerHttpRequest request = MockServerHttpRequest
          .method(HttpMethod.POST, "/api/resource")
          .header("Authorization", "Basic dXNlcjpwYXNz")
          .header("Origin", "https://attacker.example")
          .header("Content-Type", "application/x-www-form-urlencoded")
          .build();
      MockServerWebExchange ex = MockServerWebExchange.from(request);

      boolean reached = runThroughRealFilter(csrfFilter, ex);

      assertThat(reached).isFalse();
      assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void Authorization_Basic_헤더가_있어도_ignore_path는_통과() throws Exception {
      KeycloakSecurityProperties props = baseProperties();
      props.getCsrf().setIgnorePaths(List.of("/webhook/**"));
      CsrfWebFilter csrfFilter = buildRealCsrfFilter(props);

      MockServerWebExchange ex = exchangeWithHeader("POST", "/webhook/event",
          "Authorization", "Basic dXNlcjpwYXNz");

      assertThat(runThroughRealFilter(csrfFilter, ex))
          .as("ignore-paths에 명시적으로 등록된 경로는 여전히 면제되어야 한다")
          .isTrue();
    }

    @Test
    void basicAuth_비활성화여도_CSRF_보호_결과는_동일() throws Exception {
      // Advisory 3 이후로는 basic-auth.enabled 값이 CSRF 판단에 영향을 주지 않는다.
      KeycloakSecurityProperties props = baseProperties();
      props.getBasicAuth().setEnabled(false);
      CsrfWebFilter csrfFilter = buildRealCsrfFilter(props);

      MockServerWebExchange ex = exchangeWithHeader("POST", "/api/resource",
          "Authorization", "Basic dXNlcjpwYXNz");
      boolean reached = runThroughRealFilter(csrfFilter, ex);

      assertThat(reached).isFalse();
      assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }
  }
}
