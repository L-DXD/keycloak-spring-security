package com.ids.keycloak.security.config;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.ids.keycloak.security.authentication.KeycloakAuthentication;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisIndexedHttpSession;

/**
 * Redis 세션 저장소 설정.
 * <p>
 * keycloak.session.store-type=redis 일 때 활성화됩니다.
 * 다중 인스턴스 환경 및 세션 영속성이 필요한 경우 사용합니다.
 * </p>
 * <p>
 * 이 설정은 Spring Boot의 RedisAutoConfiguration에 의해 구성된
 * RedisConnectionFactory를 사용합니다. 따라서 Redis 연결 설정은
 * spring.data.redis.* 프로퍼티로 관리합니다.
 * </p>
 *
 * <h3>사용자 프로젝트 의존성 요구사항</h3>
 * <pre>
 * dependencies {
 *     implementation 'org.springframework.boot:spring-boot-starter-data-redis'
 *     implementation 'org.springframework.session:spring-session-data-redis'
 * }
 * </pre>
 *
 * <h3>세션 만료 시간 설정</h3>
 * <pre>
 * keycloak:
 *   security:
 *     session:
 *       store-type: redis
 *       timeout: 1h  # 세션 만료 시간 (기본값: 30m)
 * </pre>
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "keycloak.security.session", name = "store-type", havingValue = "redis")
@ConditionalOnClass(name = {
    "org.springframework.data.redis.connection.RedisConnectionFactory",
    "org.springframework.session.data.redis.RedisIndexedSessionRepository"
})
@AutoConfigureAfter(name = "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration")
@AutoConfigureBefore(name = "org.springframework.boot.autoconfigure.session.SessionAutoConfiguration")
@EnableRedisIndexedHttpSession
@Slf4j
public class RedisSessionConfiguration {

  /**
   * Redis namespace 설정.
   * spring.session.redis.namespace 프로퍼티를 사용하며, 없으면 기본값 사용.
   */
  @Value("${spring.session.redis.namespace:${spring.application.name:spring:session}}")
  private String redisNamespace;

  /**
   * Spring Session의 Redis 직렬화 방식을 JDK 기본 직렬화에서 JSON으로 교체합니다.
   *
   * <p>JDK 기본 직렬화(ObjectOutputStream)는 다음 문제를 가집니다.
   * <ul>
   *   <li>역직렬화 시 가젯 체인 기반 RCE 위험 (CWE-502)</li>
   *   <li>클래스 버전 불일치 시 {@code InvalidClassException} 발생</li>
   *   <li>다른 언어 클라이언트와 호환 불가</li>
   * </ul>
   * {@link GenericJackson2JsonRedisSerializer}는 JSON 형식으로 직렬화하며,
   * Spring Security Jackson 모듈을 등록하여 {@code Authentication}, {@code Principal},
   * {@code GrantedAuthority} 등 보안 객체의 Jackson 직렬화를 지원합니다.
   * </p>
   *
   * <p><b>N-3 직렬화 보강:</b><br>
   * {@code SecurityJackson2Modules}의 default typing이 활성화된 환경에서
   * JWT claims 맵({@code Map<String, Object>}) 내의 {@code Long} 타입 값(iat/exp 등)이
   * {@code ["java.lang.Long", 123]} 형태로 직렬화됩니다. 역직렬화 시
   * {@code AllowlistTypeIdResolver}가 이를 거부합니다.
   * {@link KeycloakSecurityJackson2Module}을 {@code OAuth2ClientJackson2Module} 이후에 등록하여
   * {@link OidcIdToken}·{@link OidcUserInfo}에 대해 커스텀 {@link OidcIdTokenDeserializer}/
   * {@link OidcUserInfoDeserializer}를 등록합니다. 이 Deserializer는 내부적으로 claims 맵을
   * {@link PlainClaimsMapDeserializer}로 파싱하여 AllowlistTypeIdResolver를 우회합니다.
   * </p>
   *
   * <p>커스텀 직렬화기를 사용하려면 {@code springSessionDefaultRedisSerializer} 이름으로
   * 직접 {@link RedisSerializer} 빈을 등록하세요(이 빈이 생략됩니다).</p>
   */
  @Bean("springSessionDefaultRedisSerializer")
  @ConditionalOnMissingBean(name = "springSessionDefaultRedisSerializer")
  public RedisSerializer<Object> springSessionDefaultRedisSerializer() {
    ObjectMapper mapper = new ObjectMapper();

    // 1. Spring Security 도메인 객체 직렬화 지원 + default typing 활성화
    //    (OAuth2ClientJackson2Module이 OidcIdToken mixin을 등록)
    mapper.registerModules(SecurityJackson2Modules.getModules(this.getClass().getClassLoader()));

    // 2. N-3: KeycloakSecurityJackson2Module을 마지막에 등록.
    //    - OidcIdToken/OidcUserInfo: 커스텀 Deserializer로 claims Long 문제 해결
    //    - KeycloakPrincipal/KeycloakAuthentication: allowlist mixin 등록
    mapper.registerModule(new KeycloakSecurityJackson2Module());

    log.info(
        "Keycloak Session: Redis 직렬화 방식을 JSON(GenericJackson2JsonRedisSerializer)으로 설정합니다. "
            + "(Spring Security 모듈 + Keycloak 커스텀 클래스 allowlist mixin 등록)");
    return new GenericJackson2JsonRedisSerializer(mapper);
  }

  // ---------------------------------------------------------------------------
  // KeycloakSecurityJackson2Module
  // ---------------------------------------------------------------------------

  /**
   * Keycloak 보안 객체의 Jackson 직렬화를 지원하는 모듈.
   *
   * <p>{@code OAuth2ClientJackson2Module} 이후에 등록되어야 합니다.
   * {@code setupModule()}에서 직접 Deserializer를 등록하므로 mixin 방식보다
   * 우선순위가 높습니다.</p>
   *
   * <ul>
   *   <li>{@link KeycloakPrincipal} — AllowlistTypeIdResolver 허용 mixin 등록</li>
   *   <li>{@link KeycloakAuthentication} — AllowlistTypeIdResolver 허용 mixin 등록</li>
   *   <li>{@link OidcIdToken} — 커스텀 Deserializer로 claims Long 문제 해결</li>
   *   <li>{@link OidcUserInfo} — 커스텀 Deserializer로 claims 처리</li>
   * </ul>
   */
  static class KeycloakSecurityJackson2Module extends SimpleModule {

    KeycloakSecurityJackson2Module() {
      super(KeycloakSecurityJackson2Module.class.getName(),
          new Version(1, 0, 0, null, "com.ids.keycloak", "keycloak-spring-security-web-starter"));
      // SimpleModule에 Deserializer 직접 등록 — addDeserializer는 setMixInAnnotations보다 우선순위 높음
      addDeserializer(OidcIdToken.class, new OidcIdTokenDeserializer());
      addDeserializer(OidcUserInfo.class, new OidcUserInfoDeserializer());
    }

    @Override
    public void setupModule(SetupContext context) {
      super.setupModule(context); // addDeserializer 반영
      // AllowlistTypeIdResolver: KeycloakPrincipal, KeycloakAuthentication 허용
      context.setMixInAnnotations(KeycloakPrincipal.class, KeycloakPrincipalMixin.class);
      context.setMixInAnnotations(KeycloakAuthentication.class, KeycloakAuthenticationMixin.class);
    }
  }

  // ---------------------------------------------------------------------------
  // allowlist mixin — 커스텀 Keycloak 도메인 클래스
  // ---------------------------------------------------------------------------

  /** allowlist mixin — {@link KeycloakPrincipal} */
  @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
  abstract static class KeycloakPrincipalMixin {

  }

  /** allowlist mixin — {@link KeycloakAuthentication} */
  @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
  abstract static class KeycloakAuthenticationMixin {

  }

  // ---------------------------------------------------------------------------
  // OidcIdToken / OidcUserInfo 커스텀 Deserializer
  // ---------------------------------------------------------------------------

  /**
   * {@link OidcIdToken}을 역직렬화하는 커스텀 Deserializer.
   *
   * <p>{@code OAuth2ClientJackson2Module}의 {@code OidcIdTokenMixin}을 대체합니다.
   * JSON에서 {@code tokenValue}, {@code issuedAt}, {@code expiresAt}, {@code claims}를 읽어
   * {@link OidcIdToken}을 생성합니다. {@code claims} 맵은 {@link PlainClaimsMapDeserializer}로
   * 파싱하여 {@code AllowlistTypeIdResolver}의 Long 제한을 우회합니다.</p>
   */
  static class OidcIdTokenDeserializer extends StdDeserializer<OidcIdToken> {

    OidcIdTokenDeserializer() {
      super(OidcIdToken.class);
    }

    @Override
    public OidcIdToken deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
      JsonNode node = p.getCodec().readTree(p);

      String tokenValue = node.has("tokenValue") ? node.get("tokenValue").asText() : null;
      Instant issuedAt = parseInstant(node, "issuedAt");
      Instant expiresAt = parseInstant(node, "expiresAt");
      Map<String, Object> claims = PlainClaimsMapDeserializer.parseNodeAsMap(node.get("claims"));

      return new OidcIdToken(tokenValue, issuedAt, expiresAt, claims);
    }

    private Instant parseInstant(JsonNode parent, String field) {
      JsonNode node = parent.get(field);
      if (node == null || node.isNull()) {
        return null;
      }
      // Instant는 {"epochSecond": ..., "nano": ...} 객체 또는 숫자로 직렬화될 수 있음
      if (node.isObject()) {
        long epochSecond = node.has("epochSecond") ? node.get("epochSecond").asLong() : 0;
        int nano = node.has("nano") ? node.get("nano").asInt() : 0;
        return Instant.ofEpochSecond(epochSecond, nano);
      }
      if (node.isNumber()) {
        return Instant.ofEpochSecond(node.asLong());
      }
      return null;
    }
  }

  /**
   * {@link OidcUserInfo}를 역직렬화하는 커스텀 Deserializer.
   *
   * <p>{@code OAuth2ClientJackson2Module}의 {@code OidcUserInfoMixin}을 대체합니다.
   * {@code claims} 맵을 {@link PlainClaimsMapDeserializer}로 파싱합니다.</p>
   */
  static class OidcUserInfoDeserializer extends StdDeserializer<OidcUserInfo> {

    OidcUserInfoDeserializer() {
      super(OidcUserInfo.class);
    }

    @Override
    public OidcUserInfo deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
      JsonNode node = p.getCodec().readTree(p);
      Map<String, Object> claims = PlainClaimsMapDeserializer.parseNodeAsMap(node.get("claims"));
      return new OidcUserInfo(claims);
    }
  }

  // ---------------------------------------------------------------------------
  // PlainClaimsMapDeserializer
  // ---------------------------------------------------------------------------

  /**
   * JWT claims {@code Map<String, Object>}를 타입 정보 없이 plain 값으로 역직렬화하는 유틸리티.
   *
   * <p>{@code SecurityJackson2Modules}의 default typing이 활성화되면, claims 맵 내 값들이
   * {@code ["java.lang.Long", 1234567890]} 형태의 배열로 직렬화됩니다.
   * {@code AllowlistTypeIdResolver}는 {@code java.lang.Long}을 거부하므로 역직렬화가 실패합니다.
   * 이 클래스는 {@link JsonNode}를 직접 파싱하여 plain Java 타입으로 변환하므로,
   * AllowlistTypeIdResolver를 거치지 않습니다.</p>
   *
   * <p>지원 타입: {@code String}, {@code Long}, {@code Integer}, {@code Double},
   * {@code Boolean}, {@code null}, 중첩 {@code Map}, {@code List}</p>
   */
  static class PlainClaimsMapDeserializer extends StdDeserializer<Map<String, Object>> {

    PlainClaimsMapDeserializer() {
      super(Map.class);
    }

    @Override
    public Map<String, Object> deserialize(JsonParser p, DeserializationContext ctxt)
        throws IOException {
      JsonNode node = p.getCodec().readTree(p);
      return parseNodeAsMap(node);
    }

    /**
     * {@link JsonNode}에서 {@code Map<String, Object>}를 파싱합니다 (static 유틸리티).
     *
     * <p>default typing으로 생성된 {@code ["java.lang.Long", 123]} 배열 값도 올바르게 처리합니다.</p>
     */
    static Map<String, Object> parseNodeAsMap(JsonNode node) {
      if (node == null || node.isNull()) {
        return new LinkedHashMap<>();
      }
      Map<String, Object> result = new LinkedHashMap<>();
      node.fields().forEachRemaining(entry ->
          result.put(entry.getKey(), parseNodeValue(entry.getValue())));
      return result;
    }

    /**
     * {@link JsonNode}를 plain Java 값으로 변환합니다.
     *
     * <p>배열({@code START_ARRAY})이면 default typing 배열({@code ["TypeName", value]}) 여부를
     * 확인하여 실제 값만 추출합니다.</p>
     */
    private static Object parseNodeValue(JsonNode node) {
      if (node == null || node.isNull()) {
        return null;
      }
      if (node.isTextual()) {
        return node.asText();
      }
      if (node.isBoolean()) {
        return node.asBoolean();
      }
      if (node.isIntegralNumber()) {
        long v = node.asLong();
        return (v >= Integer.MIN_VALUE && v <= Integer.MAX_VALUE) ? (int) v : v;
      }
      if (node.isFloatingPointNumber()) {
        return node.asDouble();
      }
      if (node.isObject()) {
        return parseNodeAsMap(node);
      }
      if (node.isArray()) {
        return parseNodeArray(node);
      }
      return null;
    }

    /**
     * 배열 노드를 파싱합니다.
     *
     * <p>배열의 첫 번째 요소가 알려진 타입 이름 문자열이면 default typing 배열로 간주하고
     * 두 번째 요소(실제 값)를 반환합니다. 그렇지 않으면 일반 List로 파싱합니다.</p>
     */
    private static Object parseNodeArray(JsonNode arrayNode) {
      if (arrayNode.isEmpty()) {
        return new ArrayList<>();
      }
      JsonNode first = arrayNode.get(0);
      if (first.isTextual() && isKnownTypeName(first.asText())) {
        // default typing 배열: ["TypeName", value] — 타입 이름을 무시하고 실제 값만 반환
        if (arrayNode.size() >= 2) {
          return parseNodeValue(arrayNode.get(1));
        }
        return null;
      }
      // 일반 배열
      List<Object> list = new ArrayList<>();
      arrayNode.forEach(item -> list.add(parseNodeValue(item)));
      return list;
    }

    /**
     * default typing에서 사용되는 알려진 Java 타입 이름인지 확인합니다.
     */
    private static boolean isKnownTypeName(String name) {
      return name.equals("java.lang.Long")
          || name.equals("java.lang.Integer")
          || name.equals("java.lang.Double")
          || name.equals("java.lang.Float")
          || name.equals("java.lang.Boolean")
          || name.equals("java.lang.String")
          || name.equals("java.lang.Short")
          || name.equals("java.lang.Byte")
          || name.equals("java.math.BigDecimal")
          || name.equals("java.math.BigInteger")
          || name.startsWith("java.util.ImmutableCollections")
          || name.startsWith("java.util.Collections$")
          || name.equals("java.util.ArrayList")
          || name.equals("java.util.LinkedList")
          || name.equals("java.util.HashMap")
          || name.equals("java.util.LinkedHashMap")
          || name.equals("java.util.TreeMap");
    }
  }

  /**
   * 세션 저장소의 기본 만료 시간을 설정합니다.
   * keycloak.security.session.timeout 프로퍼티 값을 사용합니다.
   *
   * <p>@EnableRedisHttpSession의 maxInactiveIntervalInSeconds 속성은 상수여야 하므로
   * 동적 설정을 위해 SessionRepositoryCustomizer를 사용합니다.</p>
   */
  @Bean
  public org.springframework.session.config.SessionRepositoryCustomizer<
      org.springframework.session.data.redis.RedisIndexedSessionRepository>
      springSessionRepositoryCustomizer(KeycloakSecurityProperties properties) {
    return repository -> {
      Duration timeout = properties.getSession().getTimeout();
      repository.setDefaultMaxInactiveInterval(timeout);

      if (redisNamespace != null && !redisNamespace.isBlank()) {
        repository.setRedisKeyNamespace(redisNamespace);
      }

      log.info(
          "Keycloak Session: Redis 세션 저장소가 활성화되었습니다. (만료 시간: {}초, Namespace: {})",
          timeout.toSeconds(), redisNamespace);
    };
  }
}
