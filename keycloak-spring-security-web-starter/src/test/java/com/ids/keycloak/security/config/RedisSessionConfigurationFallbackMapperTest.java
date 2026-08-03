package com.ids.keycloak.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BiFunction;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;
import org.springframework.session.MapSession;
import org.springframework.session.config.SessionRepositoryCustomizer;
import org.springframework.session.data.redis.RedisIndexedSessionRepository;

/**
 * {@link RedisSessionConfiguration#springSessionRepositoryCustomizer}가 등록하는 폴백
 * {@code RedisSessionMapper}를 검증한다 (a4315c9, 항목 5).
 *
 * <p>{@code createFallbackSessionMapper}는 private이므로 리플렉션 대신, 실제 소비자
 * ({@code RedisIndexedSessionRepository})가 사용하는 공개 API인
 * {@link RedisIndexedSessionRepository#setRedisSessionMapper(BiFunction)} 호출을 캡처해 실제
 * 등록된 매퍼 함수를 꺼내 검증한다 — production 로직을 복제하지 않는다.</p>
 */
class RedisSessionConfigurationFallbackMapperTest {

  @SuppressWarnings("unchecked")
  private BiFunction<String, Map<String, Object>, MapSession> resolveRegisteredMapper() {
    RedisSessionConfiguration configuration = new RedisSessionConfiguration();
    KeycloakSecurityProperties properties = new KeycloakSecurityProperties();

    SessionRepositoryCustomizer<RedisIndexedSessionRepository> customizer =
        configuration.springSessionRepositoryCustomizer(properties);

    RedisIndexedSessionRepository repository = mock(RedisIndexedSessionRepository.class);
    customizer.customize(repository);

    ArgumentCaptor<BiFunction> captor = ArgumentCaptor.forClass(BiFunction.class);
    verify(repository).setRedisSessionMapper(captor.capture());
    return (BiFunction<String, Map<String, Object>, MapSession>) captor.getValue();
  }

  private Map<String, Object> normalSessionHash() {
    Map<String, Object> hash = new HashMap<>();
    hash.put("creationTime", Instant.now().toEpochMilli());
    hash.put("lastAccessedTime", Instant.now().toEpochMilli());
    hash.put("maxInactiveInterval", 1800);
    hash.put("sessionAttr:KEYCLOAK_REFRESH_TOKEN", "refresh-token-value");
    return hash;
  }

  @Nested
  class 정상_세션_해시 {

    @Test
    void 정상_세션_해시는_그대로_MapSession으로_매핑된다() {
      BiFunction<String, Map<String, Object>, MapSession> mapper = resolveRegisteredMapper();
      String sessionId = "normal-session-id";

      MapSession session = mapper.apply(sessionId, normalSessionHash());

      assertThat(session).isNotNull();
      assertThat(session.getId()).isEqualTo(sessionId);
      String refreshToken = session.getAttribute("KEYCLOAK_REFRESH_TOKEN");
      assertThat(refreshToken).isEqualTo("refresh-token-value");
    }

    @Test
    void 정상_세션_해시_매핑에서는_예외가_발생하지_않는다() {
      BiFunction<String, Map<String, Object>, MapSession> mapper = resolveRegisteredMapper();

      assertThatCode(() -> mapper.apply("normal-session-id", normalSessionHash()))
          .doesNotThrowAnyException();
    }
  }

  @Nested
  class 손상된_세션_해시_creationTime_누락 {

    @Test
    void creationTime이_없으면_IllegalStateException_대신_null을_반환한다() {
      BiFunction<String, Map<String, Object>, MapSession> mapper = resolveRegisteredMapper();
      Map<String, Object> corruptedHash = new HashMap<>();
      corruptedHash.put("lastAccessedTime", Instant.now().toEpochMilli());
      corruptedHash.put("maxInactiveInterval", 1800);

      MapSession result = mapper.apply("corrupted-session-id", corruptedHash);

      assertThat(result)
          .as("손상된 세션은 예외 전파(HTTP 500) 대신 null(=세션 없음, 재로그인 유도)로 처리되어야 한다")
          .isNull();
    }

    @Test
    void creationTime이_없으면_예외를_던지지_않는다() {
      BiFunction<String, Map<String, Object>, MapSession> mapper = resolveRegisteredMapper();
      Map<String, Object> corruptedHash = new HashMap<>();
      corruptedHash.put("lastAccessedTime", Instant.now().toEpochMilli());
      corruptedHash.put("maxInactiveInterval", 1800);

      assertThatCode(() -> mapper.apply("corrupted-session-id", corruptedHash))
          .as("정리(cleanup) 단계 실패까지 포함해 apply() 밖으로는 어떤 예외도 전파되면 안 된다")
          .doesNotThrowAnyException();
    }

    @Test
    void creationTime이_없으면_손상을_감지했다는_WARN_로그가_남는다() {
      BiFunction<String, Map<String, Object>, MapSession> mapper = resolveRegisteredMapper();

      Logger configLogger = (Logger) LoggerFactory.getLogger(RedisSessionConfiguration.class);
      ListAppender<ILoggingEvent> logAppender = new ListAppender<>();
      logAppender.start();
      configLogger.addAppender(logAppender);
      configLogger.setLevel(Level.ALL);

      Map<String, Object> corruptedHash = new HashMap<>();
      corruptedHash.put("lastAccessedTime", Instant.now().toEpochMilli());
      corruptedHash.put("maxInactiveInterval", 1800);

      try {
        mapper.apply("corrupted-session-id", corruptedHash);

        boolean hasWarnLog = logAppender.list.stream()
            .anyMatch(e -> e.getLevel() == Level.WARN
                && e.getFormattedMessage().contains("손상된 Redis 세션을 감지"));
        assertThat(hasWarnLog)
            .as("조용한 데이터 손실 방지를 위해 손상 감지 사실이 WARN으로 남아야 한다")
            .isTrue();
      } finally {
        configLogger.detachAppender(logAppender);
        logAppender.stop();
      }
    }
  }

  @Nested
  class 손상된_세션_해시_다른_필수필드_누락 {

    @Test
    void lastAccessedTime이_없어도_null을_반환한다() {
      BiFunction<String, Map<String, Object>, MapSession> mapper = resolveRegisteredMapper();
      Map<String, Object> corruptedHash = new HashMap<>();
      corruptedHash.put("creationTime", Instant.now().toEpochMilli());
      corruptedHash.put("maxInactiveInterval", 1800);

      MapSession result = mapper.apply("corrupted-session-id", corruptedHash);

      assertThat(result).isNull();
    }

    @Test
    void maxInactiveInterval이_없어도_null을_반환한다() {
      BiFunction<String, Map<String, Object>, MapSession> mapper = resolveRegisteredMapper();
      Map<String, Object> corruptedHash = new HashMap<>();
      corruptedHash.put("creationTime", Instant.now().toEpochMilli());
      corruptedHash.put("lastAccessedTime", Instant.now().toEpochMilli());

      MapSession result = mapper.apply("corrupted-session-id", corruptedHash);

      assertThat(result).isNull();
    }
  }

  @Nested
  class 저장소_설정_회귀 {

    @Test
    void springSessionRepositoryCustomizer는_defaultMaxInactiveInterval을_설정한다() {
      RedisSessionConfiguration configuration = new RedisSessionConfiguration();
      KeycloakSecurityProperties properties = new KeycloakSecurityProperties();

      SessionRepositoryCustomizer<RedisIndexedSessionRepository> customizer =
          configuration.springSessionRepositoryCustomizer(properties);

      RedisIndexedSessionRepository repository = mock(RedisIndexedSessionRepository.class);
      customizer.customize(repository);

      verify(repository).setDefaultMaxInactiveInterval(properties.getSession().getTimeout());
      verify(repository).setRedisSessionMapper(any());
    }
  }
}
