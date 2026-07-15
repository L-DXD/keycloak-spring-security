package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.authentication.KeycloakAuthentication;
import com.ids.keycloak.security.config.RedisSessionConfiguration.KeycloakSecurityJackson2Module;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;

/**
 * N-3: Redis 세션 직렬화 round-trip 검증 테스트.
 *
 * <p>{@link RedisSessionConfiguration}이 등록하는 {@link GenericJackson2JsonRedisSerializer}가
 * {@link KeycloakPrincipal}, {@link OidcIdToken}, {@link OidcUserInfo},
 * {@link KeycloakAuthentication} 등 커스텀 객체를 직렬화→역직렬화(round-trip) 할 수 있는지
 * 검증합니다.</p>
 *
 * <p>역직렬화 실패 시 세션 조회 시 예외가 발생하여 인증이 깨지므로 반드시 통과해야 합니다.</p>
 */
class RedisSessionSerializationRoundTripTest {

  private GenericJackson2JsonRedisSerializer serializer;

  @BeforeEach
  void setUp() {
    // RedisSessionConfiguration.springSessionDefaultRedisSerializer() 와 동일한 설정
    ObjectMapper mapper = new ObjectMapper();
    mapper.registerModules(SecurityJackson2Modules.getModules(this.getClass().getClassLoader()));
    mapper.registerModule(new KeycloakSecurityJackson2Module());
    serializer = new GenericJackson2JsonRedisSerializer(mapper);
  }

  // ------------------------------------------------------------------
  // OidcIdToken round-trip
  // ------------------------------------------------------------------

  @Nested
  class OidcIdToken_직렬화 {

    @Test
    void OidcIdToken_round_trip_성공() {
      Map<String, Object> claims = Map.of(
          "sub", "user-123",
          "iss", "https://keycloak.example.com/realms/test",
          "iat", Instant.now().getEpochSecond(),   // Long 타입
          "exp", Instant.now().plusSeconds(3600).getEpochSecond()  // Long 타입
      );
      OidcIdToken original = new OidcIdToken(
          "dummy.id.token", Instant.now(), Instant.now().plusSeconds(3600), claims);

      byte[] serialized = serializer.serialize(original);
      assertThat(serialized).isNotNull().isNotEmpty();

      Object deserialized = serializer.deserialize(serialized);
      assertThat(deserialized).isNotNull().isInstanceOf(OidcIdToken.class);

      OidcIdToken result = (OidcIdToken) deserialized;
      assertThat(result.getTokenValue()).isEqualTo("dummy.id.token");
      assertThat(result.getClaimAsString("sub")).isEqualTo("user-123");
      // iat/exp가 숫자 타입으로 올바르게 역직렬화되어야 함
      assertThat(result.getClaims().get("iat")).isInstanceOfAny(Long.class, Integer.class);
    }
  }

  // ------------------------------------------------------------------
  // OidcUserInfo round-trip
  // ------------------------------------------------------------------

  @Nested
  class OidcUserInfo_직렬화 {

    @Test
    void OidcUserInfo_round_trip_성공() {
      Map<String, Object> claims = Map.of(
          "sub", "user-123",
          "preferred_username", "testuser",
          "email", "testuser@example.com"
      );
      OidcUserInfo original = new OidcUserInfo(claims);

      byte[] serialized = serializer.serialize(original);
      assertThat(serialized).isNotNull().isNotEmpty();

      Object deserialized = serializer.deserialize(serialized);
      assertThat(deserialized).isNotNull().isInstanceOf(OidcUserInfo.class);

      OidcUserInfo result = (OidcUserInfo) deserialized;
      assertThat(result.getClaimAsString("sub")).isEqualTo("user-123");
      assertThat(result.getClaimAsString("preferred_username")).isEqualTo("testuser");
      assertThat(result.getClaimAsString("email")).isEqualTo("testuser@example.com");
    }

    @Test
    void OidcUserInfo_null_직렬화_성공() {
      // null 직렬화는 구현체에 따라 다를 수 있음 — 예외 없이 처리되면 통과
      assertThatCode(() -> serializer.serialize(null)).doesNotThrowAnyException();
    }
  }

  // ------------------------------------------------------------------
  // KeycloakPrincipal round-trip
  // ------------------------------------------------------------------

  @Nested
  class KeycloakPrincipal_직렬화 {

    @Test
    void KeycloakPrincipal_userInfo_있음_round_trip_성공() {
      Map<String, Object> idTokenClaims = Map.of(
          "sub", "user-123",
          "iat", Instant.now().getEpochSecond(),
          "exp", Instant.now().plusSeconds(3600).getEpochSecond()
      );
      OidcIdToken idToken = new OidcIdToken(
          "dummy.id.token", Instant.now(), Instant.now().plusSeconds(3600), idTokenClaims);

      Map<String, Object> userInfoClaims = Map.of(
          "sub", "user-123",
          "preferred_username", "testuser"
      );
      OidcUserInfo userInfo = new OidcUserInfo(userInfoClaims);

      KeycloakPrincipal original = new KeycloakPrincipal(
          "user-123",
          List.of(new SimpleGrantedAuthority("ROLE_USER")),
          idToken,
          userInfo
      );

      byte[] serialized = serializer.serialize(original);
      assertThat(serialized).isNotNull().isNotEmpty();

      Object deserialized = serializer.deserialize(serialized);
      assertThat(deserialized).isNotNull().isInstanceOf(KeycloakPrincipal.class);

      KeycloakPrincipal result = (KeycloakPrincipal) deserialized;
      assertThat(result.getName()).isEqualTo("user-123");
      assertThat(result.getAuthorities()).hasSize(1);
      assertThat(result.getIdToken()).isNotNull();
      assertThat(result.getIdToken().getTokenValue()).isEqualTo("dummy.id.token");
      assertThat(result.getUserInfo()).isNotNull();
      assertThat(result.getUserInfo().getClaimAsString("preferred_username")).isEqualTo("testuser");
    }

    @Test
    void KeycloakPrincipal_userInfo_null_round_trip_성공() {
      Map<String, Object> idTokenClaims = Map.of(
          "sub", "user-456",
          "iat", Instant.now().getEpochSecond(),
          "exp", Instant.now().plusSeconds(3600).getEpochSecond()
      );
      OidcIdToken idToken = new OidcIdToken(
          "dummy.id.token2", Instant.now(), Instant.now().plusSeconds(3600), idTokenClaims);

      KeycloakPrincipal original = new KeycloakPrincipal(
          "user-456",
          Collections.emptyList(),
          idToken,
          null  // UserInfo null — require-user-info=false 기본 동작 시 발생
      );

      byte[] serialized = serializer.serialize(original);
      assertThat(serialized).isNotNull().isNotEmpty();

      Object deserialized = serializer.deserialize(serialized);
      assertThat(deserialized).isNotNull().isInstanceOf(KeycloakPrincipal.class);

      KeycloakPrincipal result = (KeycloakPrincipal) deserialized;
      assertThat(result.getName()).isEqualTo("user-456");
      assertThat(result.getAuthorities()).isEmpty();
      assertThat(result.getIdToken()).isNotNull();
      assertThat(result.getUserInfo()).isNull();
    }

    @Test
    void KeycloakPrincipal_빈_권한_round_trip_성공() {
      // require-user-info=false 시 빈 권한으로 인증 성공하는 경우
      Map<String, Object> idTokenClaims = Map.of(
          "sub", "user-789",
          "iat", Instant.now().getEpochSecond(),
          "exp", Instant.now().plusSeconds(3600).getEpochSecond()
      );
      OidcIdToken idToken = new OidcIdToken(
          "dummy.id.token3", Instant.now(), Instant.now().plusSeconds(3600), idTokenClaims);

      KeycloakPrincipal original = new KeycloakPrincipal(
          "user-789",
          Collections.emptyList(),
          idToken,
          null
      );

      byte[] serialized = serializer.serialize(original);
      Object deserialized = serializer.deserialize(serialized);

      KeycloakPrincipal result = (KeycloakPrincipal) deserialized;
      assertThat(result.getName()).isEqualTo("user-789");
      assertThat(result.getAuthorities()).isEmpty();
    }
  }

  // ------------------------------------------------------------------
  // KeycloakAuthentication round-trip
  // ------------------------------------------------------------------

  @Nested
  class KeycloakAuthentication_직렬화 {

    @Test
    void KeycloakAuthentication_인증완료_round_trip_성공() {
      Map<String, Object> idTokenClaims = Map.of(
          "sub", "user-123",
          "iat", Instant.now().getEpochSecond(),
          "exp", Instant.now().plusSeconds(3600).getEpochSecond()
      );
      OidcIdToken idToken = new OidcIdToken(
          "valid.id.token", Instant.now(), Instant.now().plusSeconds(3600), idTokenClaims);

      KeycloakPrincipal principal = new KeycloakPrincipal(
          "user-123",
          List.of(new SimpleGrantedAuthority("ROLE_USER")),
          idToken,
          null
      );

      KeycloakAuthentication original =
          new KeycloakAuthentication(principal, "valid.id.token", "valid.access.token", true);

      byte[] serialized = serializer.serialize(original);
      assertThat(serialized).isNotNull().isNotEmpty();

      Object deserialized = serializer.deserialize(serialized);
      assertThat(deserialized).isNotNull().isInstanceOf(KeycloakAuthentication.class);

      KeycloakAuthentication result = (KeycloakAuthentication) deserialized;
      assertThat(result.isAuthenticated()).isTrue();
      assertThat(result.getPrincipal()).isNotNull();
      assertThat(result.getPrincipal().getName()).isEqualTo("user-123");
      assertThat(result.getIdToken()).isEqualTo("valid.id.token");
      assertThat(result.getAccessToken()).isEqualTo("valid.access.token");
      assertThat(result.getAuthorities()).hasSize(1);
    }
  }

  // ------------------------------------------------------------------
  // 2.0.2 회귀 테스트 — 실제 운영 ID Token 클레임 형태
  // ------------------------------------------------------------------

  /**
   * 2.0.1까지의 회귀(regression) 재현 테스트.
   *
   * <p>위의 기존 테스트들은 {@code aud} 클레임을 포함하지 않아 다음 결함을 놓쳤다.</p>
   * <ul>
   *   <li>{@code KeycloakPrincipal}은 {@code OidcUser}/{@code IdTokenClaimAccessor}의
   *   {@code getAudience()}(setter 없는 파생 {@code List<String>} getter)를 상속한다. {@code aud}는
   *   OIDC 필수 클레임이라 실제 ID Token에는 항상 존재하며, 2.0.1의 mixin(getter 기반 introspection)은
   *   이 파생 getter까지 프로퍼티로 잡아 역직렬화 시
   *   {@code InvalidDefinitionException: Problem deserializing 'setterless' property ("audience"):
   *   no way to handle typed deser with setterless yet}로 실패했다 — 모든 인증 요청에서 세션 복원이
   *   깨지는 원인.</li>
   *   <li>{@code Jwt.getClaims()}(Spring {@code MappedJwtClaimSetConverter})는 {@code iat}/{@code exp}를
   *   {@code Long}이 아닌 {@code java.time.Instant}로 변환한다. 2.0.1의
   *   {@code PlainClaimsMapDeserializer.isKnownTypeName()}에는 {@code java.time.Instant}가 없어
   *   예외는 없지만 값이 2-원소 {@code List}로 조용히 손상되었다.</li>
   * </ul>
   */
  @Nested
  class 실제_운영_클레임_형태_회귀테스트 {

    @Test
    void aud_클레임_포함_KeycloakAuthentication_round_trip_성공() {
      Instant now = Instant.now();
      // Jwt.getClaims()가 실제로 만드는 형태: aud=List<String>, iat/exp=Instant,
      // auth_time=Long(Keycloak가 추가하는, Spring이 자동 변환하지 않는 커스텀 숫자 클레임)
      Map<String, Object> idTokenClaims = Map.of(
          "sub", "user-123",
          "aud", List.of("my-client"),
          "iat", now,
          "exp", now.plusSeconds(3600),
          "auth_time", now.getEpochSecond()
      );
      OidcIdToken idToken = new OidcIdToken(
          "valid.id.token", now, now.plusSeconds(3600), idTokenClaims);

      KeycloakPrincipal principal = new KeycloakPrincipal(
          "user-123",
          List.of(new SimpleGrantedAuthority("ROLE_USER")),
          idToken,
          null
      );

      KeycloakAuthentication original =
          new KeycloakAuthentication(principal, "valid.id.token", "valid.access.token", true);

      byte[] serialized = serializer.serialize(original);
      Object deserialized = serializer.deserialize(serialized);
      assertThat(deserialized).isInstanceOf(KeycloakAuthentication.class);

      KeycloakAuthentication result = (KeycloakAuthentication) deserialized;
      assertThat(result.getPrincipal().getAudience()).containsExactly("my-client");

      Map<String, Object> resultClaims = result.getPrincipal().getIdToken().getClaims();
      assertThat(resultClaims.get("iat")).isInstanceOf(Instant.class);
      assertThat((Instant) resultClaims.get("iat"))
          .isCloseTo(now, org.assertj.core.api.Assertions.within(1, java.time.temporal.ChronoUnit.SECONDS));
      assertThat(resultClaims.get("auth_time")).isEqualTo(now.getEpochSecond());
    }
  }
}
