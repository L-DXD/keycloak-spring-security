package com.ids.keycloak.security.config;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.ids.keycloak.security.authentication.KeycloakAuthentication;
import com.ids.keycloak.security.model.KeycloakPrincipal;
import com.ids.keycloak.security.util.LogMaskingUtil;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
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
   *
   * <p><b>code-review High #2 (2.0.2):</b> {@link JavaTimeModule}을 명시적으로 등록합니다.
   * {@code SecurityJackson2Modules}는 {@code jackson-datatype-jsr310}이 클래스패스에 있을 때만
   * 조건부로 등록하므로, 이 라이브러리 자체의 보장으로는 부족합니다. 명시 등록으로 {@code Instant}
   * 등 {@code java.time.*} 값의 직렬화 형태(초 단위 소수 타임스탬프)를 안정적으로 고정합니다.
   * {@link PlainClaimsMapDeserializer}는 이 형태를 전제로 {@code Instant}를 복원합니다.</p>
   */
  @Bean("springSessionDefaultRedisSerializer")
  @ConditionalOnMissingBean(name = "springSessionDefaultRedisSerializer")
  public RedisSerializer<Object> springSessionDefaultRedisSerializer() {
    ObjectMapper mapper = new ObjectMapper();

    // 1. Spring Security 도메인 객체 직렬화 지원 + default typing 활성화
    //    (OAuth2ClientJackson2Module이 OidcIdToken mixin을 등록)
    mapper.registerModules(SecurityJackson2Modules.getModules(this.getClass().getClassLoader()));

    // 1-1. code-review High #2: java.time.* 직렬화 형태를 명시적으로 고정
    //      (SecurityJackson2Modules의 조건부 등록에 의존하지 않음)
    mapper.registerModule(new JavaTimeModule());

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

  /**
   * allowlist mixin — {@link KeycloakPrincipal}.
   *
   * <p><b>2.0.2 패치(치명적 회귀):</b> {@code fieldVisibility=ANY, getterVisibility=NONE}로
   * 필드 기반 introspection을 강제합니다. {@code KeycloakPrincipal}은 {@link
   * org.springframework.security.oauth2.core.oidc.IdTokenClaimAccessor}를 구현하므로
   * {@code getAudience()}(aud 클레임, {@code List<String>})·{@code getAuthenticationMethods()}(amr
   * 클레임)처럼 setter 없는 파생 컬렉션 getter를 다수 상속합니다. 기본(getter 기반) introspection에서는
   * default typing이 활성화된 상태에서 이 getter들도 직렬화 대상 프로퍼티로 잡히고, 역직렬화 시
   * Jackson이 {@code SetterlessProperty}로 처리하려다
   * {@code InvalidDefinitionException: Problem deserializing 'setterless' property ("audience"):
   * no way to handle typed deser with setterless yet}를 던집니다. {@code aud} 클레임은 OIDC 필수
   * 클레임이므로 실제 운영 ID Token에는 항상 존재해 <b>모든 인증 요청에서 세션 역직렬화가 실패</b>합니다
   * (Spring 공식 {@code DefaultOidcUserMixin}/{@code OidcIdTokenMixin}과 동일한 필드 기반 패턴 적용).
   * 필드 기반으로 전환하면 실제 생성자 파라미터(name/authorities/idToken/userInfo)만 프로퍼티로 잡혀
   * 파생 getter는 전부 배제됩니다.</p>
   */
  @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
  @JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY,
      getterVisibility = JsonAutoDetect.Visibility.NONE,
      isGetterVisibility = JsonAutoDetect.Visibility.NONE)
  @JsonIgnoreProperties(value = {"attributes", "claims"}, ignoreUnknown = true)
  abstract static class KeycloakPrincipalMixin {

  }

  /**
   * allowlist mixin — {@link KeycloakAuthentication}.
   *
   * <p><b>2.0.2 패치:</b> {@link KeycloakPrincipalMixin}과 동일한 이유로 필드 기반 introspection을
   * 적용합니다. {@code KeycloakAuthentication}은 {@code AbstractAuthenticationToken}을 상속하며,
   * 이 슈퍼클래스가 노출하는 setter 없는 파생 getter({@code getName()} 등)를 getter 기반
   * introspection에서 프로퍼티로 잡을 경우 유사한 역직렬화 실패 위험이 있어 동일하게 방지합니다.</p>
   */
  @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
  @JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY,
      getterVisibility = JsonAutoDetect.Visibility.NONE,
      isGetterVisibility = JsonAutoDetect.Visibility.NONE)
  @JsonIgnoreProperties(ignoreUnknown = true)
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
   * <p>{@code SecurityJackson2Modules}의 default typing이 활성화되면, claims 맵처럼 값의 정적
   * 타입이 {@code Object}(즉, 실행 시점에야 구체 타입을 알 수 있는 위치)인 경우 Jackson이 타입
   * 정보를 함께 기록합니다. 이 라이브러리가 사용하는
   * {@link GenericJackson2JsonRedisSerializer}(PROPERTY 방식 default typing)는 실제로 두 가지
   * 형태를 모두 사용합니다.</p>
   * <ul>
   *   <li>스칼라/배열 값 — {@code ["TypeName", value]} 2원소 배열 (예:
   *   {@code ["java.lang.Long", 1234567890]}, {@code ["java.net.URL", "https://..."]})</li>
   *   <li>객체(Map) 값 — 값 자체에 {@code "@class"} 속성이 추가됨 (예:
   *   {@code {"@class":"java.util.LinkedHashMap", "sub":"user-1"}})</li>
   * </ul>
   * <p>{@code AllowlistTypeIdResolver}는 이런 타입들 대부분(예: {@code java.lang.Long})을
   * 거부하므로 표준 역직렬화 경로로는 복원할 수 없습니다. 이 클래스는 {@link JsonNode}를 직접
   * 순회하여 위 두 형태의 타입 메타데이터를 제거하고 plain Java 타입으로 복원하므로
   * {@code AllowlistTypeIdResolver}를 거치지 않습니다.</p>
   *
   * <p><b>code-review High #1 (2.0.2, silent claim 손상):</b> 이전 구현은 {@code isKnownTypeName()}
   * allowlist에 없는 타입 이름을 만나면 배열을 <b>그냥 일반 2원소 List로 오인식</b>했습니다. 운영
   * ID Token의 {@code iss}는 {@code OidcIdTokenDecoderFactory}(내부적으로 실제
   * {@code NimbusJwtDecoder}를 사용)의 기본 claim 변환기가 항상 {@code java.net.URL}로 변환하는데,
   * 구버전 allowlist에는 없어 {@code ["java.net.URL", "https://..."]}가
   * {@code [URL 문자열, 실제 URL 문자열]} 형태의 2원소 List로 조용히 손상되었습니다({@code iss}는
   * OIDC 필수 클레임이라 항상 발생 — 예외는 없어 발견이 어려움). {@code resource_access}/
   * {@code realm_access}처럼 중첩된 객체 값도 {@code @class} 속성이 그대로 claim 키로 섞여
   * 들어가는 별도의 오염이 있었습니다.</p>
   *
   * <p>이번 패치는 화이트리스트를 계속 나열하는 대신(whack-a-mole) <b>범용 언랩 휴리스틱</b>을
   * 적용합니다.</p>
   * <ol>
   *   <li>배열 값이 정확히 2개이고 첫 번째 요소가 FQCN 형태의 문자열
   *   ({@code 패키지.클래스}, 정규식 {@link #FQCN_PATTERN})이면 타입 래퍼로 간주하고 두 번째
   *   요소(실제 값)를 언랩 대상으로 삼습니다.</li>
   *   <li>알려진 스칼라(Long/Integer/Short/Byte/Double/Float/Boolean/String/BigDecimal/
   *   BigInteger)·시간 타입(Instant/Date)·{@code java.net.URL}/{@code URI}는 실제 타입의 값으로
   *   정확히 복원합니다.</li>
   *   <li>그 외 타입은, 언랩 대상 값 자체가 JSON 객체/배열이면(= Map/List로 표현 가능한 구조라는
   *   뜻) 구체 클래스 이름(예: {@code java.util.HashMap}, {@code net.minidev.json.JSONObject},
   *   {@code com.nimbusds.jose.shaded.gson.internal.LinkedTreeMap} 등 무엇이든)을 몰라도
   *   Map/List로 안전하게 복원합니다.</li>
   *   <li>그마저도 아닌, 진짜 미인식 스칼라 타입 래퍼는 <b>warn 로그를 남기고 원본 구조
   *   ({@code [typeName, value]})를 그대로 보존</b>합니다. silent 손상을 내는 대신 실패를
   *   드러내어 필요 시 이 클래스에 처리를 추가할 수 있게 합니다.</li>
   * </ol>
   *
   * <p>객체(Map) 값에 섞여 들어오는 {@code "@class"} 속성은 {@link #parseNodeAsMap(JsonNode)}에서
   * (중첩 여부와 무관하게) 항상 제거합니다.</p>
   *
   * <p><b>code-review High #2 (2.0.2):</b> {@code java.time.Instant}는
   * jackson-datatype-jsr310의 기본 직렬화 형태(초 단위 소수 타임스탬프 숫자, 예:
   * {@code 1737039434.096212}) 기준으로 복원합니다. 이 형태가 실제로 보장되도록
   * {@code springSessionDefaultRedisSerializer()}에 {@link JavaTimeModule}을 명시 등록했습니다.
   * {@code java.util.Date}는 Instant와 달리 <b>초 단위 소수가 아닌 epoch 밀리초(정수)</b>로
   * 직렬화되므로 별도 분기로 처리합니다(둘을 같은 방식으로 처리하면 약 1000배 오차가 발생).</p>
   */
  static class PlainClaimsMapDeserializer extends StdDeserializer<Map<String, Object>> {

    /** GenericJackson2JsonRedisSerializer(PROPERTY 방식 default typing)가 객체 값에 삽입하는 타입 속성. */
    private static final String JACKSON_TYPE_PROPERTY = "@class";

    /** {@code패키지.클래스} 형태(점으로 구분된 2개 이상의 세그먼트)를 판별하는 정규식. */
    private static final Pattern FQCN_PATTERN =
        Pattern.compile("^[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)+$");

    private static final Set<String> KNOWN_SCALAR_TYPE_NAMES = Set.of(
        "java.lang.Long",
        "java.lang.Integer",
        "java.lang.Short",
        "java.lang.Byte",
        "java.lang.Double",
        "java.lang.Float",
        "java.lang.Boolean",
        "java.lang.String",
        "java.math.BigDecimal",
        "java.math.BigInteger");

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
     * <p>{@code "@class"} 속성(default typing이 객체 값에 삽입하는 타입 메타데이터)은 실제
     * claim이 아니므로 제외합니다.</p>
     */
    static Map<String, Object> parseNodeAsMap(JsonNode node) {
      if (node == null || node.isNull()) {
        return new LinkedHashMap<>();
      }
      Map<String, Object> result = new LinkedHashMap<>();
      node.fields().forEachRemaining(entry -> {
        if (JACKSON_TYPE_PROPERTY.equals(entry.getKey())) {
          return;
        }
        result.put(entry.getKey(), parseNodeValue(entry.getValue()));
      });
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
     * <p>정확히 2개 요소이고 첫 번째가 FQCN 형태 문자열이면 default typing 타입 래퍼로 간주하고
     * {@link #unwrapTypedValue(String, JsonNode)}로 위임합니다. 그렇지 않으면 일반 List로
     * 파싱합니다.</p>
     */
    private static Object parseNodeArray(JsonNode arrayNode) {
      if (arrayNode.isEmpty()) {
        return new ArrayList<>();
      }
      if (arrayNode.size() == 2 && arrayNode.get(0).isTextual()) {
        String typeName = arrayNode.get(0).asText();
        if (FQCN_PATTERN.matcher(typeName).matches()) {
          return unwrapTypedValue(typeName, arrayNode.get(1));
        }
      }
      // 일반 배열
      List<Object> list = new ArrayList<>();
      arrayNode.forEach(item -> list.add(parseNodeValue(item)));
      return list;
    }

    /**
     * {@code ["TypeName", value]} 타입 래퍼를 언랩합니다.
     *
     * <p>알려진 타입은 실제 값으로 정확히 복원하고, Map/List로 표현 가능한 구조는 타입 이름에
     * 상관없이 안전하게 복원합니다. 그 외(미인식 스칼라 타입)는 silent 손상을 피하기 위해 warn
     * 로그를 남기고 원본 구조({@code [typeName, value]})를 그대로 보존합니다.</p>
     */
    private static Object unwrapTypedValue(String typeName, JsonNode valueNode) {
      if (isTemporalTypeName(typeName)) {
        return "java.time.Instant".equals(typeName)
            ? parseTemporalValue(valueNode)
            : parseDateValue(valueNode);
      }
      if (isNetTypeName(typeName)) {
        return parseNetValue(typeName, valueNode);
      }
      if (KNOWN_SCALAR_TYPE_NAMES.contains(typeName)) {
        return parseScalarValue(typeName, valueNode);
      }
      if (valueNode != null && (valueNode.isObject() || valueNode.isArray())) {
        // Map/List 등 구조적 타입 — 구체 클래스 이름(HashMap/LinkedTreeMap/JSONObject/
        // ImmutableCollections$... 등 무엇이든)에 관계없이 JSON 형태(object/array) 자체가 구조를
        // 결정하므로 타입 이름을 몰라도 안전하게 복원 가능
        return parseNodeValue(valueNode);
      }
      // 미인식 타입 래퍼(스칼라인데 알려지지 않은 타입) — 추측 대신 원본 보존 + 경고 로그
      // (silent 손상 방지: allowlist를 계속 나열하는 대신, 모르는 타입은 있는 그대로 보존한다)
      log.warn(
          "Redis 세션 claims 역직렬화: 인식되지 않은 타입 래퍼 '{}' 를 만났습니다. 값을 "
              + "[typeName, value] 형태로 보존합니다 — PlainClaimsMapDeserializer에 해당 타입 "
              + "처리 추가를 검토하세요.",
          typeName);
      List<Object> preserved = new ArrayList<>(2);
      preserved.add(typeName);
      preserved.add(parseNodeValue(valueNode));
      return preserved;
    }

    /**
     * {@code java.time.Instant}로 default typing 래핑된 값을 실제 {@link Instant}로 복원합니다.
     *
     * <p>jackson-datatype-jsr310의 기본 직렬화 형태(초 단위 소수 타임스탬프 숫자, 예:
     * {@code 1737039434.096212}), ISO-8601 문자열, {@code {"epochSecond":..,"nano":..}} 객체
     * 형태를 모두 지원합니다.</p>
     */
    private static Instant parseTemporalValue(JsonNode node) {
      if (node == null || node.isNull()) {
        return null;
      }
      if (node.isNumber()) {
        java.math.BigDecimal seconds = node.decimalValue();
        long epochSecond = seconds.longValue();
        long nanos = seconds.subtract(java.math.BigDecimal.valueOf(epochSecond))
            .multiply(java.math.BigDecimal.valueOf(1_000_000_000L))
            .longValue();
        return Instant.ofEpochSecond(epochSecond, nanos);
      }
      if (node.isTextual()) {
        return Instant.parse(node.asText());
      }
      if (node.isObject()) {
        long epochSecond = node.has("epochSecond") ? node.get("epochSecond").asLong() : 0;
        int nano = node.has("nano") ? node.get("nano").asInt() : 0;
        return Instant.ofEpochSecond(epochSecond, nano);
      }
      return null;
    }

    /**
     * {@code java.util.Date}로 default typing 래핑된 값을 실제 {@link Date}로 복원합니다.
     *
     * <p>Jackson 기본 직렬화 형태는 <b>epoch 밀리초(정수)</b>입니다. {@link Instant}(초 단위
     * 소수)와 단위가 다르므로 같은 방식으로 처리하면 약 1000배 오차가 발생합니다.</p>
     */
    private static Date parseDateValue(JsonNode node) {
      if (node == null || node.isNull()) {
        return null;
      }
      if (node.isNumber()) {
        return new Date(node.asLong());
      }
      if (node.isTextual()) {
        return Date.from(Instant.parse(node.asText()));
      }
      if (node.isObject() && node.has("epochSecond")) {
        long epochSecond = node.get("epochSecond").asLong();
        return new Date(epochSecond * 1000L);
      }
      return null;
    }

    /**
     * {@code java.net.URL}/{@code java.net.URI}로 default typing 래핑된 값을 실제 객체로
     * 복원합니다. 복원에 실패하면(형식 오류 등) warn 로그를 남기고 원본 문자열을 반환합니다
     * (예외를 던져 세션 전체 역직렬화를 실패시키지 않음).
     */
    private static Object parseNetValue(String typeName, JsonNode node) {
      if (node == null || !node.isTextual()) {
        return null;
      }
      String text = node.asText();
      try {
        if ("java.net.URL".equals(typeName)) {
          // java.net.URL(String) 생성자는 Java 20부터 deprecated — URI 경유로 생성
          return new URI(text).toURL();
        }
        return new URI(text);
      } catch (MalformedURLException | URISyntaxException | IllegalArgumentException ex) {
        log.warn(
            "Redis 세션 claims 역직렬화: {} 값 '{}' 복원 실패 - 원본 문자열로 대체합니다.",
            typeName, text, ex);
        return text;
      }
    }

    /**
     * 알려진 boxed 스칼라 타입 이름에 맞춰 값을 정확한 타입으로 복원합니다.
     *
     * <p>{@link #parseNodeValue(JsonNode)}의 크기 기반 int/long 자동 추론에 맡기지 않고 타입
     * 이름을 그대로 존중합니다 — 그렇지 않으면 예컨대 {@code java.lang.Long} 값이 {@code int}
     * 범위 안에 들 때 {@code Integer}로 복원되어 (라운드트립 후) 타입이 바뀌는 손상이 됩니다.</p>
     */
    private static Object parseScalarValue(String typeName, JsonNode node) {
      if (node == null || node.isNull()) {
        return null;
      }
      switch (typeName) {
        case "java.lang.Long":
          return node.asLong();
        case "java.lang.Integer":
          return node.asInt();
        case "java.lang.Short":
          return (short) node.asInt();
        case "java.lang.Byte":
          return (byte) node.asInt();
        case "java.lang.Double":
          return node.asDouble();
        case "java.lang.Float":
          return (float) node.asDouble();
        case "java.lang.Boolean":
          return node.asBoolean();
        case "java.lang.String":
          return node.asText();
        case "java.math.BigDecimal":
          return node.decimalValue();
        case "java.math.BigInteger":
          return node.bigIntegerValue();
        default:
          return parseNodeValue(node);
      }
    }

    private static boolean isTemporalTypeName(String name) {
      return "java.time.Instant".equals(name) || "java.util.Date".equals(name);
    }

    private static boolean isNetTypeName(String name) {
      return "java.net.URL".equals(name) || "java.net.URI".equals(name);
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

      // 항목 5: 손상된 세션(필수 필드 누락)에 대한 폴백 매퍼를 등록한다. 등록하지 않으면
      // Spring Session의 기본 RedisSessionMapper가 IllegalStateException을 던지고, 이를
      // RedisIndexedSessionRepository.getSession()이 try/catch 없이 그대로 전파해 HTTP 500이
      // 발생한다(그 브라우저는 영구적으로 재로그인조차 못 하게 됨).
      repository.setRedisSessionMapper(createFallbackSessionMapper(repository));

      log.info(
          "Keycloak Session: Redis 세션 저장소가 활성화되었습니다. (만료 시간: {}초, Namespace: {})",
          timeout.toSeconds(), redisNamespace);
    };
  }

  // ---------------------------------------------------------------------------
  // 항목 5: 손상 세션 내성 — 폴백 RedisSessionMapper
  // ---------------------------------------------------------------------------

  /**
   * {@code RedisIndexedSessionRepository}의 package-private {@code getSessionKey(String)}를
   * 리플렉션으로 조회한 핸들이다. 손상된 세션의 Redis 해시 키를 정리(cleanup)할 때만 사용되며,
   * 조회에 실패해도(향후 Spring Session 버전에서 메서드가 사라지거나 이름이 바뀌는 경우) 정리
   * 기능만 비활성화될 뿐, 손상 세션을 null로 처리해 500을 막는 핵심 동작에는 영향이 없다.
   */
  private static final java.lang.reflect.Method GET_SESSION_KEY_METHOD = resolveGetSessionKeyMethod();

  private static java.lang.reflect.Method resolveGetSessionKeyMethod() {
    java.lang.reflect.Method method = org.springframework.util.ReflectionUtils.findMethod(
        org.springframework.session.data.redis.RedisIndexedSessionRepository.class,
        "getSessionKey", String.class);
    if (method != null) {
      org.springframework.util.ReflectionUtils.makeAccessible(method);
    } else {
      log.warn(
          "Keycloak Session: RedisIndexedSessionRepository#getSessionKey(String)를 찾을 수 없어 "
              + "손상된 세션의 Redis 키 자동 정리가 비활성화됩니다(라이브러리 버전 비호환 가능성). "
              + "손상 세션을 미인증으로 처리하여 HTTP 500을 방지하는 핵심 동작은 계속 유지됩니다.");
    }
    return method;
  }

  /**
   * 기본 {@link org.springframework.session.data.redis.RedisSessionMapper}를 감싸, 필수 필드
   * 누락으로 인한 {@link IllegalStateException}을 손상 세션으로 간주해 warn 로그 + Redis 키 정리
   * 후 {@code null}(= 세션 없음, 정상 재로그인 유도)로 변환하는 폴백 매퍼를 생성한다.
   *
   * <p>세션ID는 추적·식별 목적의 값이므로 {@link LogMaskingUtil}로 마스킹해서만 로그에 남긴다
   * (조용한 데이터 손실 방지 — 손상 사실과 정리 결과를 반드시 로그로 남긴다).</p>
   */
  private static java.util.function.BiFunction<String, java.util.Map<String, Object>,
      org.springframework.session.MapSession> createFallbackSessionMapper(
      org.springframework.session.data.redis.RedisIndexedSessionRepository repository) {
    org.springframework.session.data.redis.RedisSessionMapper delegate =
        new org.springframework.session.data.redis.RedisSessionMapper();

    return (sessionId, sessionMap) -> {
      try {
        return delegate.apply(sessionId, sessionMap);
      } catch (IllegalStateException e) {
        log.warn(
            "Keycloak Session: 손상된 Redis 세션을 감지했습니다(필수 필드 누락: {}). 세션ID={} 을 "
                + "미인증(재로그인 필요)으로 처리하고 정리를 시도합니다.",
            e.getMessage(), LogMaskingUtil.maskIdentifier(sessionId));
        cleanupCorruptedSession(repository, sessionId);
        return null;
      }
    };
  }

  /**
   * 손상된 세션의 원본 Redis 해시 키를 삭제한다(best-effort). 원인 불명의 부분 정리 실패로 인해
   * 세션이 무한정 재로그인을 방해하는 상태가 되지 않도록, 정리에 실패해도 예외를 전파하지 않는다
   * (호출부의 핵심 동작인 "손상 세션 → 미인증 처리"는 이미 완료된 뒤이므로 안전하다).
   */
  private static void cleanupCorruptedSession(
      org.springframework.session.data.redis.RedisIndexedSessionRepository repository, String sessionId) {
    if (GET_SESSION_KEY_METHOD == null) {
      return;
    }
    try {
      String redisKey = (String) GET_SESSION_KEY_METHOD.invoke(repository, sessionId);
      Boolean deleted = repository.getSessionRedisOperations().delete(redisKey);
      log.warn("Keycloak Session: 손상된 Redis 세션 키를 정리했습니다. key={}, deleted={}",
          LogMaskingUtil.maskIdentifier(redisKey), deleted);
    } catch (Exception cleanupEx) {
      log.warn(
          "Keycloak Session: 손상된 Redis 세션 키 정리에 실패했습니다(수동 정리가 필요할 수 있음). "
              + "세션ID={}, 원인={}",
          LogMaskingUtil.maskIdentifier(sessionId), cleanupEx.getMessage());
    }
  }
}
