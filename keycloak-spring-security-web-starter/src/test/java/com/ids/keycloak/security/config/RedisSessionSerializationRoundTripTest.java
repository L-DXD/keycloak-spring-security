package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.keycloak.security.authentication.KeycloakAuthentication;
import com.ids.keycloak.security.config.RedisSessionConfiguration.KeycloakSecurityJackson2Module;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

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
  // 2.0.2 회귀 테스트 — 실제 NimbusJwtDecoder 산출 Jwt.getClaims() 기반
  // ------------------------------------------------------------------

  /**
   * 2.0.1까지의 회귀(regression) 재현 + code-review High #1/#2(2.0.2) 검증 테스트.
   *
   * <p>과거 테스트들은 손으로 만든 {@code Map.of(...)} claims를 사용해 다음 결함들을 놓쳤다.</p>
   * <ul>
   *   <li>{@code KeycloakPrincipal}이 상속하는 setter 없는 파생 getter(예: {@code getAudience()})가
   *   getter 기반 introspection에서 프로퍼티로 잡혀 역직렬화가 실패하던 결함(2.0.1) — 필드 기반
   *   introspection(mixin)으로 수정됨.</li>
   *   <li><b>High #1</b>: 운영 ID Token의 {@code iss}는 {@link OidcIdTokenDecoderFactory}(실제
   *   {@link NimbusJwtDecoder}를 내부에서 사용)의 기본 claim 변환기가 {@code java.net.URL}로
   *   변환하는데, 구버전 allowlist에 없어 2원소 {@code List}로 조용히 손상되었다. 중첩된
   *   {@code resource_access}/{@code realm_access} 객체 값에는 {@code @class} 타입 메타데이터가
   *   claim 키로 섞여 들어가는 오염도 있었다.</li>
   *   <li><b>High #2</b>: {@code iat}/{@code exp}/{@code auth_time}은 {@code Instant}로 변환되는데
   *   {@code JavaTimeModule} 미등록 시 직렬화 형태가 불안정했다.</li>
   * </ul>
   *
   * <p>아래 테스트는 손으로 만든 claims 대신, 로컬 RSA 키로 자체 서명한 JWT를 실제
   * {@link NimbusJwtDecoder}로 디코딩하고 운영 코드와 동일한
   * {@link OidcIdTokenDecoderFactory#createDefaultClaimTypeConverter()}를 적용해 얻은
   * {@link Jwt#getClaims()}를 사용한다(네트워크 불필요 — JWKS 조회 없이 공개키로 즉시 검증).</p>
   */
  @Nested
  class 실제_NimbusJwtDecoder_클레임_기반_회귀테스트 {

    /**
     * 로컬 RSA 키로 자체 서명한 JWT를 실제 {@link NimbusJwtDecoder} + 운영과 동일한
     * {@link OidcIdTokenDecoderFactory} 기본 claim 변환기로 디코딩해 실제 운영 ID Token과
     * 동일한 형태({@code iss}=URL, {@code aud}=List, {@code iat}/{@code exp}=Instant, 중첩
     * {@code resource_access}/{@code realm_access}, 커스텀 Long 클레임)의 {@link Jwt}를 만든다.
     */
    private Jwt decodeRealIdTokenClaims() throws Exception {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();

      Instant now = Instant.now();
      JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
          .issuer("https://keycloak.example.com/realms/test")
          .subject("user-123")
          .audience("my-client")
          .issueTime(Date.from(now))
          .expirationTime(Date.from(now.plusSeconds(3600)))
          // Keycloak가 추가하는, 기본 claim 변환기가 건드리지 않는 커스텀 숫자 클레임(Long 유지 검증용)
          .claim("org_id", 9_999_999_999L)
          .claim("resource_access", Map.of(
              "my-client", Map.of("roles", List.of("ROLE_USER", "ROLE_ADMIN"))))
          .claim("realm_access", Map.of("roles", List.of("offline_access", "uma_authorization")))
          .build();

      SignedJWT signedJwt =
          new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), claimsSet);
      signedJwt.sign(new RSASSASigner((RSAPrivateKey) keyPair.getPrivate()));
      String token = signedJwt.serialize();

      NimbusJwtDecoder decoder =
          NimbusJwtDecoder.withPublicKey((RSAPublicKey) keyPair.getPublic()).build();
      // 운영 코드(OidcIdTokenDecoderFactory.createDecoder)와 동일한 claim 변환기를 재사용:
      // iss -> java.net.URL, aud/amr -> List<String>, iat/exp/auth_time -> Instant 등
      decoder.setClaimSetConverter(OidcIdTokenDecoderFactory.createDefaultClaimTypeConverter());

      return decoder.decode(token);
    }

    /**
     * claims 키집합 + 값 타입 + 값이 원본과 동일한지(잉여 {@code @class} 키 없음, 손상 없음)를
     * 단언한다.
     *
     * <p>{@code iss}(URL)는 {@link URL#equals}가 호스트명 DNS 조회를 수행할 수 있어 테스트
     * 환경에 따라 느려지거나 결과가 달라질 위험이 있으므로 {@code toString()} 비교로 대체하고,
     * 나머지는 {@link Map#equals}로 한 번에 비교한다(값 타입이 바뀌면 예:
     * {@code Long(1).equals(Integer(1))}이 {@code false}이므로 타입 손상도 함께 잡힌다).</p>
     */
    private void assertClaimsRoundTripIntact(Map<String, Object> expected, Map<String, Object> actual) {
      assertThat(actual.keySet()).containsExactlyInAnyOrderElementsOf(expected.keySet());

      assertThat(actual.get("iss")).isInstanceOf(URL.class);
      assertThat(actual.get("iss").toString()).isEqualTo(expected.get("iss").toString());

      Map<String, Object> expectedWithoutIss = new LinkedHashMap<>(expected);
      Map<String, Object> actualWithoutIss = new LinkedHashMap<>(actual);
      expectedWithoutIss.remove("iss");
      actualWithoutIss.remove("iss");
      assertThat(actualWithoutIss).isEqualTo(expectedWithoutIss);
    }

    @Test
    void 실제_클레임_사전조건_확인() throws Exception {
      // 아래 라운드트립 테스트가 실제로 취약했던 형태를 검증하고 있는지 사전 확인
      Map<String, Object> claims = decodeRealIdTokenClaims().getClaims();

      assertThat(claims.get("iss")).isInstanceOf(URL.class);
      assertThat(claims.get("aud")).isInstanceOf(List.class);
      assertThat(claims.get("iat")).isInstanceOf(Instant.class);
      assertThat(claims.get("exp")).isInstanceOf(Instant.class);
      assertThat(claims.get("org_id")).isInstanceOf(Long.class);
      assertThat(claims.get("resource_access")).isInstanceOf(Map.class);
      assertThat(claims.get("realm_access")).isInstanceOf(Map.class);
    }

    @Test
    void 실제_클레임_GenericJackson2JsonRedisSerializer_왕복_손상없음() throws Exception {
      Jwt jwt = decodeRealIdTokenClaims();
      Map<String, Object> claims = jwt.getClaims();

      OidcIdToken idToken = new OidcIdToken(
          "signed.jwt.token", jwt.getIssuedAt(), jwt.getExpiresAt(), claims);
      KeycloakPrincipal principal = new KeycloakPrincipal(
          "user-123", List.of(new SimpleGrantedAuthority("ROLE_USER")), idToken, null);
      KeycloakAuthentication original =
          new KeycloakAuthentication(principal, "signed.jwt.token", "access.token.value", true);

      byte[] serialized = serializer.serialize(original);
      Object deserialized = serializer.deserialize(serialized);
      assertThat(deserialized).isInstanceOf(KeycloakAuthentication.class);

      KeycloakAuthentication result = (KeycloakAuthentication) deserialized;
      assertThat(result.getPrincipal().getAudience()).containsExactly("my-client");

      Map<String, Object> resultClaims = result.getPrincipal().getIdToken().getClaims();
      assertClaimsRoundTripIntact(claims, resultClaims);
      assertThat(result.getPrincipal().getIdToken().getIssuedAt()).isEqualTo(idToken.getIssuedAt());
      assertThat(result.getPrincipal().getIdToken().getExpiresAt()).isEqualTo(idToken.getExpiresAt());
    }

    @Test
    void 실제_클레임_JdkSerializationRedisSerializer_왕복_손상없음() throws Exception {
      Jwt jwt = decodeRealIdTokenClaims();
      Map<String, Object> claims = jwt.getClaims();

      OidcIdToken idToken = new OidcIdToken(
          "signed.jwt.token", jwt.getIssuedAt(), jwt.getExpiresAt(), claims);
      KeycloakPrincipal principal = new KeycloakPrincipal(
          "user-123", List.of(new SimpleGrantedAuthority("ROLE_USER")), idToken, null);
      KeycloakAuthentication original =
          new KeycloakAuthentication(principal, "signed.jwt.token", "access.token.value", true);

      JdkSerializationRedisSerializer jdkSerializer = new JdkSerializationRedisSerializer();
      byte[] serialized = jdkSerializer.serialize(original);
      Object deserialized = jdkSerializer.deserialize(serialized);
      assertThat(deserialized).isInstanceOf(KeycloakAuthentication.class);

      KeycloakAuthentication result = (KeycloakAuthentication) deserialized;
      Map<String, Object> resultClaims = result.getPrincipal().getIdToken().getClaims();
      // JDK 직렬화는 Jackson default typing/@class 메타데이터 경로를 타지 않으므로
      // (원본 객체 그래프를 그대로 직렬화) claims가 완전히 동일해야 한다.
      assertThat(resultClaims).isEqualTo(claims);
    }
  }
}
