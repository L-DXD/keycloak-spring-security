# 12. Async Dispatch에서 SecurityContext 문제와 해결

## 개요

`StreamingResponseBody`, `DeferredResult`, `Callable` 등 비동기 처리 시 발생할 수 있는 SecurityContext 관련 문제와 라이브러리의 해결 방안을 설명합니다.

---

## 문제 상황

### 환경
- Spring Boot 3.x / Spring Security 6.x
- `StreamingResponseBody`를 사용한 대용량 파일 다운로드

### 현상
- 비동기 처리 중 `AnonymousAuthenticationToken` 발생
- `AccessDeniedException` (401/403) 오류 발생

---

## 비동기 처리의 두 가지 시나리오

### 시나리오 A: ASYNC 디스패치 (필터 체인 레벨)

```
┌─────────────────────────────────────────────────────────────┐
│ REQUEST 디스패치                                             │
│  필터 체인 → 컨트롤러 → StreamingResponseBody 반환            │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ 비동기 스트리밍 (별도 스레드)                                 │
│  writeTo(outputStream) 실행                                 │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ ASYNC 디스패치 (스트리밍 완료 후)                             │
│  필터 체인 재실행 → 응답 완료                                 │
└─────────────────────────────────────────────────────────────┘
```

**이 시나리오는 라이브러리가 해결합니다.** ✅

### 시나리오 B: writeTo() 내부에서 SecurityContext 접근

```java
@GetMapping("/download")
public StreamingResponseBody download() {
    return outputStream -> {
        // 이 코드는 별도 스레드에서 실행됨
        // 필터 체인 밖이므로 SecurityContext가 비어있음!
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        // auth = null 또는 AnonymousAuthenticationToken
    };
}
```

**이 시나리오는 라이브러리만으로 해결 불가능합니다.** ❌

---

## 라이브러리가 제공하는 해결책

### 1. shouldNotFilterAsyncDispatch/ErrorDispatch 설정

`KeycloakAuthenticationFilter`에서 ASYNC/ERROR 디스패치에서도 필터가 재실행되도록 설정합니다.

```java
// KeycloakAuthenticationFilter.java
@Override
protected boolean shouldNotFilterAsyncDispatch() {
    return false;  // ASYNC 디스패치에서도 필터 실행
}

@Override
protected boolean shouldNotFilterErrorDispatch() {
    return false;  // ERROR 디스패치에서도 필터 실행
}
```

### 2. dispatcherTypeMatchers 설정

ASYNC/ERROR 디스패치에서 URL 인가를 통과시킵니다.

```java
// KeycloakServletAutoConfiguration.java
authorize.dispatcherTypeMatchers(DispatcherType.ASYNC, DispatcherType.ERROR).permitAll();
```

### 해결되는 범위

| 시나리오 | 해결 여부 |
|---------|----------|
| ASYNC 디스패치에서 URL 접근 거부 | ✅ 해결 |
| ERROR 디스패치에서 URL 접근 거부 | ✅ 해결 |
| `writeTo()` 내부에서 SecurityContext 접근 | ❌ 미해결 |
| `writeTo()` 내부에서 `@PreAuthorize` 호출 | ❌ 미해결 |

---

## writeTo() 내부에서 SecurityContext가 필요한 경우

### 방법 1: 라이브러리 옵션 활성화 (가장 간단)

`application.yaml`에 한 줄만 추가하면 됩니다.

```yaml
keycloak:
  security:
    async:
      security-context-propagation: true
```

이 설정을 활성화하면 `StreamingResponseBody.writeTo()` 내부에서도 `SecurityContextHolder`를 사용할 수 있습니다.

```java
@GetMapping("/download")
public StreamingResponseBody download() {
    return outputStream -> {
        // security-context-propagation: true 설정 시 정상 동작
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String userId = auth.getName();
        // ...
    };
}
```

**추가 설정 옵션:**

```yaml
keycloak:
  security:
    async:
      security-context-propagation: true  # 활성화 (기본값: false)
      core-pool-size: 10                  # 스레드 풀 코어 크기 (기본값: 10)
      max-pool-size: 50                   # 스레드 풀 최대 크기 (기본값: 50)
      queue-capacity: 100                 # 작업 대기열 크기 (기본값: 100)
      thread-name-prefix: "keycloak-async-"  # 스레드 이름 접두사
```

---

### 방법 2: 컨트롤러에서 미리 캡처

```java
@GetMapping("/download")
public StreamingResponseBody download() {
    // 컨트롤러에서 미리 필요한 정보 캡처
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    String userId = auth.getName();
    List<String> roles = auth.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .toList();

    return outputStream -> {
        // writeTo() 내부에서는 캡처한 값 사용
        // SecurityContextHolder 직접 접근 X
        if (roles.contains("ROLE_ADMIN")) {
            writeAdminFile(userId, outputStream);
        } else {
            writeUserFile(userId, outputStream);
        }
    };
}
```

### 방법 3: DelegatingSecurityContextAsyncTaskExecutor 직접 설정

라이브러리 옵션 대신 직접 설정하고 싶은 경우:

```java
@Configuration
public class AsyncSecurityConfig implements WebMvcConfigurer {

    @Override
    public void configureAsyncSupport(AsyncSupportConfigurer configurer) {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(10);
        executor.setMaxPoolSize(50);
        executor.setQueueCapacity(100);
        executor.setThreadNamePrefix("async-");
        executor.initialize();

        // SecurityContext를 전파하는 Executor로 래핑
        configurer.setTaskExecutor(
            new DelegatingSecurityContextAsyncTaskExecutor(executor)
        );
    }
}
```

### 방법 4: @Async 메서드에서 SecurityContext 필요 시

```java
@Configuration
@EnableAsync
public class AsyncConfig implements AsyncConfigurer {

    @Override
    public Executor getAsyncExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(10);
        executor.setMaxPoolSize(50);
        executor.initialize();

        return new DelegatingSecurityContextAsyncTaskExecutor(executor);
    }
}
```

### 방법 5: CompletableFuture 사용 시

```java
@Service
public class FileService {

    private final ExecutorService securityAwareExecutor;

    public FileService() {
        ExecutorService rawExecutor = Executors.newFixedThreadPool(10);
        this.securityAwareExecutor = new DelegatingSecurityContextExecutorService(rawExecutor);
    }

    public CompletableFuture<byte[]> downloadFileAsync() {
        return CompletableFuture.supplyAsync(() -> {
            // SecurityContext가 전파됨
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            return generateFile(auth.getName());
        }, securityAwareExecutor);
    }
}
```

---

## 트러블슈팅

### 문제: ASYNC 디스패치에서 403 에러 발생

**확인사항:**
1. `KeycloakAuthenticationFilter`가 `AuthorizationFilter`보다 먼저 실행되는지 확인
2. 커스텀 `SecurityFilterChain`을 정의했다면 `dispatcherTypeMatchers` 설정 확인

```java
// 커스텀 SecurityFilterChain 사용 시
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.with(KeycloakHttpConfigurer.keycloak(), Customizer.withDefaults());

    http.authorizeHttpRequests(authorize -> {
        // ASYNC/ERROR 디스패치 허용 (필수!)
        authorize.dispatcherTypeMatchers(DispatcherType.ASYNC, DispatcherType.ERROR).permitAll();
        // ... 나머지 설정
    });

    return http.build();
}
```

### 문제: writeTo() 내부에서 Authentication이 null

**원인:** `writeTo()`는 필터 체인 밖에서 별도 스레드로 실행됨

**해결:**
1. 컨트롤러에서 미리 필요한 정보 캡처 (권장)
2. `DelegatingSecurityContextAsyncTaskExecutor` 설정

### 문제: @PreAuthorize가 적용된 메서드에서 AccessDenied

**원인:** 메서드 레벨 보안은 `dispatcherTypeMatchers`와 무관하게 동작

**해결:**
1. 비동기 코드에서 `@PreAuthorize` 메서드 호출 전에 인가 체크
2. `DelegatingSecurityContextAsyncTaskExecutor` 설정

---

## 요약

### 라이브러리가 제공하는 것

| 기능 | 기본 제공 | 옵션 활성화 시 |
|-----|---------|--------------|
| ASYNC/ERROR 디스패치에서 필터 체인 인증/인가 | ✅ | ✅ |
| `writeTo()` 내부에서 SecurityContext 접근 | ❌ | ✅ |
| `@PreAuthorize` 등 메서드 레벨 보안 | ❌ | ✅ |

### 가장 간단한 해결 방법

```yaml
# application.yaml
keycloak:
  security:
    async:
      security-context-propagation: true
```

이 한 줄로 `StreamingResponseBody`, `@Async`, `CompletableFuture` 등 비동기 처리에서 SecurityContext를 사용할 수 있습니다.

### 대안: 컨트롤러에서 미리 캡처
```java
@GetMapping("/download")
public StreamingResponseBody download() {
    // 1. 컨트롤러에서 필요한 정보 미리 캡처
    String userId = SecurityContextHolder.getContext().getAuthentication().getName();

    // 2. writeTo()에서는 캡처한 값 사용
    return outputStream -> {
        writeFileForUser(userId, outputStream);
    };
}
```

---

## 참고 자료

- [Spring Security - Servlet Async Integration](https://docs.spring.io/spring-security/reference/servlet/integrations/servlet-api.html#servletapi-async)
- [Spring Security - Concurrency Support](https://docs.spring.io/spring-security/reference/servlet/integrations/concurrency.html)
- [OncePerRequestFilter JavaDoc](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/filter/OncePerRequestFilter.html)
