# Redis 세션 저장소 지원 구현 계획서

## 1. 개요 (Overview)

### 1.1 배경
현재 라이브러리는 `IndexedMapSessionRepository`를 통한 **In-Memory 세션 관리**만을 기본으로 제공합니다. 이는 단일 인스턴스 환경에서는 효율적이지만, 다음과 같은 한계가 있습니다.
* **Scale-out 불가**: 다중 인스턴스 배포 시 인스턴스 간 세션 공유 불가능.
* **영속성 부재**: 애플리케이션 재시작 시 로그인 세션 소실.

### 1.2 목표
* `application.yml` 설정을 통해 **Memory** 또는 **Redis** 세션 저장소를 선택할 수 있도록 기능을 확장합니다.
* **Redis 구성 방식(Standalone, Sentinel, Cluster)** 에 구애받지 않는 유연한 구조를 제공하여 인프라 변경에 유연하게 대처합니다.

### 1.3 핵심 호환성
백채널 로그아웃 기능은 `FindByIndexNameSessionRepository` 인터페이스에 의존합니다.
* **Memory**: `IndexedMapSessionRepository` → `FindByIndexNameSessionRepository<MapSession>` 구현
* **Redis**: `RedisIndexedSessionRepository` → `FindByIndexNameSessionRepository<Session>` 구현

두 구현체 모두 동일한 인터페이스를 구현하므로, **백채널 로그아웃 기능이 Redis 환경에서도 그대로 동작**합니다.

---

## 2. 핵심 설계 방향 (Design Principles)

### 2.1 설정 주도 구성 (Configuration Driven)
사용자는 `keycloak.session.store-type` 프로퍼티를 통해 저장소 유형을 결정합니다.
* `MEMORY` (Default): 기존 방식 유지 (단일 서버용).
* `REDIS`: Redis 기반 세션 활성화 (다중 서버/고가용성용).

### 2.2 연결 설정 위임 (Delegation of Connection) **[핵심]**
본 라이브러리는 **Redis 연결(Connection)을 직접 생성하거나 관리하지 않습니다.**
* Redis 연결 설정(`host`, `port`, `sentinel`, `cluster` 등)은 Spring Boot의 표준 `RedisAutoConfiguration`에 전적으로 위임합니다.
* 라이브러리는 이미 빈으로 등록된 `RedisConnectionFactory`를 감지하여 세션 저장소 기능(`@EnableRedisHttpSession`)만 활성화합니다.
* 이를 통해 **Standalone, Sentinel, Cluster 구성을 라이브러리 코드 수정 없이 `application.yml` 설정만으로 지원**합니다.

---

## 3. 상세 구현 계획 (Implementation Details)

### Step 1: 의존성 추가 (`build.gradle`)
Redis 및 Spring Session 관련 의존성을 **선택적(Optional)** 으로 추가합니다.

```groovy
dependencies {
    // ... 기존 의존성

    // Redis Session Support (선택적 의존성)
    // 라이브러리 사용자가 Redis를 원할 때만 자신의 프로젝트에 추가하면 됨
    compileOnly 'org.springframework.boot:spring-boot-starter-data-redis'
    compileOnly 'org.springframework.session:spring-session-data-redis'
}
```

> **설계 결정**: `implementation` 대신 `compileOnly`를 사용하여 라이브러리 사용자에게 Redis 의존성을 강제하지 않습니다.
> Redis를 사용하려는 사용자는 자신의 `build.gradle`에 해당 의존성을 추가하면 됩니다.

### Step 2: 프로퍼티 정의 (`KeycloakSessionProperties`)

> **주의**: 기존 `KeycloakSecurityProperties`는 `keycloak.security` prefix를 사용합니다.
> 세션 설정은 별도의 `KeycloakSessionProperties` 클래스로 분리하여 `keycloak.session` prefix를 사용합니다.

저장소 유형 선택을 위한 Enum과 설정 클래스를 **신규 생성**합니다.

```java
// SessionStoreType.java
package com.ids.keycloak.security.config;

public enum SessionStoreType {
    MEMORY,
    REDIS
}
```

```java
// KeycloakSessionProperties.java
package com.ids.keycloak.security.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "keycloak.session")
public class KeycloakSessionProperties {

    /**
     * 세션 저장소 유형 (MEMORY 또는 REDIS)
     * 기본값: MEMORY (하위 호환성 유지)
     */
    private SessionStoreType storeType = SessionStoreType.MEMORY;
}
```

> **설계 결정**: 기존 `KeycloakSecurityProperties`를 수정하지 않고 별도 클래스로 분리하여
> 관심사 분리(Separation of Concerns)와 하위 호환성을 동시에 확보합니다.

### Step 3: AutoConfiguration 리팩토링 (`SessionConfiguration`)

`KeycloakServletAutoConfiguration` 내부의 `SessionConfiguration`을 저장소 유형에 따라 조건부로 로딩되도록 분리합니다.

> **주의사항**:
> - `@EnableSpringHttpSession`과 `@EnableRedisHttpSession`은 **동시에 사용할 수 없습니다**.
> - Redis 설정 클래스는 `@ConditionalOnClass`로 보호하여 Redis 의존성이 없을 때 `ClassNotFoundException`을 방지합니다.
> - `@EnableRedisHttpSession`이 `RedisIndexedSessionRepository`를 자동 등록하므로 별도 Bean 정의가 불필요합니다.

```java
/**
 * 세션 관리 관련 Bean 설정
 * Memory/Redis 설정을 별도 클래스로 분리하여 @Enable 어노테이션 충돌 방지
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(KeycloakSessionProperties.class)
@Slf4j
protected static class SessionConfiguration {

    // --------------------------------------------------------
    // 공통 설정 (저장소 유형과 무관하게 항상 등록)
    // --------------------------------------------------------
    @Bean
    @ConditionalOnMissingBean
    public KeycloakSessionManager keycloakSessionManager() {
        log.debug("지원 Bean을 등록합니다: [KeycloakSessionManager]");
        return new KeycloakSessionManager();
    }
}

// --------------------------------------------------------
// 1. In-Memory 설정 (Default) - 별도 최상위 클래스로 분리
// --------------------------------------------------------
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "keycloak.session", name = "store-type", havingValue = "memory", matchIfMissing = true)
@EnableSpringHttpSession
@Slf4j
class MemorySessionConfiguration {

    @Bean
    @ConditionalOnMissingBean(FindByIndexNameSessionRepository.class)
    public FindByIndexNameSessionRepository<MapSession> sessionRepository() {
        log.info("IndexedMapSessionRepository (In-Memory) 생성");
        return new IndexedMapSessionRepository(new ConcurrentHashMap<>());
    }
}

// --------------------------------------------------------
// 2. Redis 설정 - 별도 최상위 클래스로 분리
// --------------------------------------------------------
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "keycloak.session", name = "store-type", havingValue = "redis")
@ConditionalOnClass(name = "org.springframework.data.redis.connection.RedisConnectionFactory")
@AutoConfigureAfter(name = "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration")
@EnableRedisHttpSession
@Slf4j
class RedisSessionConfiguration {

    // @EnableRedisHttpSession이 RedisIndexedSessionRepository를 자동으로 Bean 등록합니다.
    // RedisIndexedSessionRepository는 FindByIndexNameSessionRepository<Session>을 구현하므로
    // 백채널 로그아웃 기능이 그대로 동작합니다.

    public RedisSessionConfiguration() {
        log.info("RedisIndexedSessionRepository (Redis) 활성화");
    }
}
```

> **Import 수정 필요**: `KeycloakServletAutoConfiguration`의 `@Import`에 새 설정 클래스들을 추가해야 합니다.
> ```java
> @Import({
>     KeycloakServletAutoConfiguration.SessionConfiguration.class,
>     MemorySessionConfiguration.class,   // 추가
>     RedisSessionConfiguration.class,    // 추가
>     // ... 기존 설정들
> })
> ```

---

## 4. 사용자 설정 가이드 (Usage Guide)

### 4.0 사전 요구사항 (Redis 사용 시)

Redis 세션 저장소를 사용하려면 **사용자 프로젝트**에 다음 의존성을 추가해야 합니다.

```groovy
// build.gradle (사용자 프로젝트)
dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-data-redis'
    implementation 'org.springframework.session:spring-session-data-redis'
}
```

> 라이브러리는 이 의존성들을 `compileOnly`로 포함하므로, 사용자가 직접 추가해야 합니다.

### 4.1 Standalone (단일 Redis)

```yaml
keycloak:
  session:
    store-type: redis

spring:
  data:
    redis:
      host: localhost
      port: 6379
      password: your_password
```

### 4.2 Sentinel (고가용성 구성)

라이브러리 코드 변경 없이 Spring Boot의 기본 설정을 그대로 사용합니다.

```yaml
keycloak:
  session:
    store-type: redis

spring:
  data:
    redis:
      sentinel:
        master: mymaster
        nodes:
          - 192.168.1.1:26379
          - 192.168.1.2:26379
          - 192.168.1.3:26379
      password: your_redis_password
```

### 4.3 Cluster (분산 구성)

```yaml
keycloak:
  session:
    store-type: redis

spring:
  data:
    redis:
      cluster:
        nodes:
          - 192.168.1.1:6379
          - 192.168.1.2:6379
          - 192.168.1.3:6379
      password: your_redis_password
```

---

## 5. 검증 및 테스트 계획 (Verification)

### 5.1 단위 테스트

조건부 설정이 올바르게 동작하는지 검증합니다.

```java
@SpringBootTest
@TestPropertySource(properties = "keycloak.session.store-type=memory")
class MemorySessionConfigurationTest {

    @Autowired
    private FindByIndexNameSessionRepository<?> sessionRepository;

    @Test
    void memory_설정_시_IndexedMapSessionRepository가_등록된다() {
        assertThat(sessionRepository).isInstanceOf(IndexedMapSessionRepository.class);
    }
}
```

### 5.2 로컬 검증

1. `keycloak.session.store-type=redis` 설정 후 애플리케이션 기동
2. Redis CLI로 세션 확인:
   ```bash
   redis-cli keys 'spring:session:*'
   ```
3. 백채널 로그아웃 테스트:
   - Keycloak에서 로그아웃 실행
   - Redis에서 해당 사용자의 세션이 삭제되었는지 확인

### 5.3 통합 테스트 (Testcontainers 권장)

다양한 Redis 환경에서의 안정성을 보장하기 위해 Testcontainers를 활용한 테스트 코드를 작성합니다.

```java
@SpringBootTest
@Testcontainers
@TestPropertySource(properties = "keycloak.session.store-type=redis")
class RedisSessionIntegrationTest {

    @Container
    static GenericContainer<?> redis = new GenericContainer<>("redis:7-alpine")
        .withExposedPorts(6379);

    @DynamicPropertySource
    static void redisProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.data.redis.host", redis::getHost);
        registry.add("spring.data.redis.port", redis::getFirstMappedPort);
    }

    @Autowired
    private FindByIndexNameSessionRepository<?> sessionRepository;

    @Test
    void redis_설정_시_RedisIndexedSessionRepository가_등록된다() {
        assertThat(sessionRepository).isInstanceOf(RedisIndexedSessionRepository.class);
    }

    @Test
    void 백채널_로그아웃_시_Principal_Name으로_세션을_검색하고_삭제한다() {
        // Given: 세션 생성 및 Principal Name 설정
        // When: findByPrincipalName 호출
        // Then: 해당 사용자의 모든 세션 반환 확인
    }
}
```

### 5.4 검증 체크리스트

| 항목 | Memory | Redis | 상태 |
|------|--------|-------|------|
| 세션 생성/조회/삭제 | - | - | ⬜ |
| Principal Name 인덱싱 | - | - | ⬜ |
| 백채널 로그아웃 | - | - | ⬜ |
| 세션 만료 처리 | - | - | ⬜ |
| 다중 인스턴스 세션 공유 | N/A | - | ⬜ |

---

## 6. 구현 시 주의사항

### 6.1 Session 타입 차이

| 저장소 | Repository 타입 | Session 타입 |
|--------|-----------------|--------------|
| Memory | `IndexedMapSessionRepository` | `MapSession` |
| Redis | `RedisIndexedSessionRepository` | `Session` |

`OidcBackChannelSessionLogoutHandler`에서 세션을 다룰 때, 제네릭 타입에 주의해야 합니다.

```java
// 현재 코드 (MapSession 전용)
private final FindByIndexNameSessionRepository<MapSession> sessionRepository;

// 수정 필요 (범용)
private final FindByIndexNameSessionRepository<? extends Session> sessionRepository;
```

### 6.2 spring.factories / AutoConfiguration.imports 등록

새로 생성한 설정 클래스들을 Spring Boot 자동 설정에 등록해야 합니다.

```
# META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports
com.ids.keycloak.security.config.MemorySessionConfiguration
com.ids.keycloak.security.config.RedisSessionConfiguration
```

### 6.3 의존성 없을 때 예외 방지

Redis 의존성이 classpath에 없을 때 `RedisSessionConfiguration` 클래스 로딩 자체가 실패할 수 있습니다.
`@ConditionalOnClass`를 **문자열**로 지정하여 이를 방지합니다.

```java
// ✅ 권장: 문자열로 지정 (클래스 로딩 시점에 안전)
@ConditionalOnClass(name = "org.springframework.data.redis.connection.RedisConnectionFactory")

// ❌ 비권장: 클래스 직접 참조 (ClassNotFoundException 발생 가능)
@ConditionalOnClass(RedisConnectionFactory.class)
```

---

## 7. 파일 변경 요약

| 파일 | 변경 유형 | 설명 |
|------|----------|------|
| `build.gradle` | 수정 | Redis 의존성 추가 (compileOnly) |
| `SessionStoreType.java` | 신규 | Enum 정의 |
| `KeycloakSessionProperties.java` | 신규 | 세션 설정 Properties |
| `MemorySessionConfiguration.java` | 신규 | In-Memory 세션 설정 |
| `RedisSessionConfiguration.java` | 신규 | Redis 세션 설정 |
| `KeycloakServletAutoConfiguration.java` | 수정 | SessionConfiguration 분리, @Import 수정 |
| `OidcBackChannelSessionLogoutHandler.java` | 수정 | Session 타입 제네릭 변경 |
| `AutoConfiguration.imports` | 수정 | 새 설정 클래스 등록 |
