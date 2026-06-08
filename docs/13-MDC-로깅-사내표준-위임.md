# 13. MDC 로깅 사내표준 위임 (v1.6.0)

> 사내 로깅 표준을 본 라이브러리(`keycloak-spring-security-web-starter`) 단일 위임으로 통합하기 위한 MDC 보강.
> 요구사항 R1~R3 + PII 마스킹 + X-Request-Id 회신을 포함합니다. (R4 응답 메트릭·R6 excludePatterns는 v1.7.0 예정)

## 1. 변경 요약

| 항목 | 내용 |
|------|------|
| **R1 (P0)** | `WebMdcContextAccessor.clear()`가 `MDC.clear()`로 외부 키까지 비우던 누수 버그 수정 → 라이브러리가 put한 키만 추적/제거 |
| **PII 마스킹** | `LoggingValueSanitizer` SPI 도입 + `DefaultPiiMaskingSanitizer` **기본 등록(on)** |
| **R2** | `userAgent` MDC 추가 (마스킹 + 256자 제한) |
| **R3** | `queryString` 정제 (URL 디코딩 + 512자 제한 + 마스킹) |
| **X-Request-Id** | traceId를 응답 헤더로 회신 |

## 2. R1 — clear() 키 누수 보정

**문제**: `WebMdcContextAccessor.clear()`가 `MDC.clear()`를 호출해, 사용자 코드/타 라이브러리가 넣은 MDC 키(도메인 컨텍스트 등)까지 전부 삭제했습니다.

**수정**: 어댑터를 통해 put한 키만 `ThreadLocal<Set<String>>`으로 추적하고, `clear()` 시 그 키들만 `MDC.remove`합니다. 사용자가 직접 `MDC.put`한 키는 보존됩니다. (스레드풀 재사용 시 `ThreadLocal`도 정리)

## 3. PII 마스킹 — `LoggingValueSanitizer` SPI

```java
@FunctionalInterface
public interface LoggingValueSanitizer {
    String sanitize(String key, String value);
}
```

- 기본 빈 `DefaultPiiMaskingSanitizer` — 이메일/휴대폰/주민번호/카드/Bearer 토큰 마스킹 (**기본 on**)
- `MdcRequestFilter`가 `query`/`userAgent`를 MDC에 넣기 직전 `sanitize(...)` 호출
- 사용자가 `LoggingValueSanitizer` 빈을 등록하면 자동 교체(`@ConditionalOnMissingBean`)

| 종류 | 원본 | 마스킹 |
|------|------|--------|
| 이메일 | `alice@example.com` | `a***@example.com` |
| 휴대폰 | `010-1234-5678` | `010-****-5678` |
| 주민번호 | `900101-1234567` | `900101-1******` |
| 카드 | `1234-5678-9012-3456` | `1234-****-****-3456` |
| Bearer | `Bearer eyJ...` | `Bearer ***` |

## 4. 신규 프로퍼티

```yaml
keycloak:
  security:
    logging:
      include-user-agent: true       # userAgent MDC 포함 (기본 true)
      return-trace-id-header: true   # 응답 X-Request-Id 회신 (기본 true)
      max-query-length: 512          # query 최대 길이
      max-user-agent-length: 256     # userAgent 최대 길이
      include-query-string: false    # (기존) query MDC 포함
```

## 5. Migration 가이드 (v1.5.x → v1.6.0)

### ⚠️ Breaking change — PII 마스킹 기본 on
- 기존에는 query/userAgent가 마스킹 없이 기록됐습니다. v1.6.0부터 **기본으로 PII가 마스킹**됩니다.
- 로그에서 이메일/전화번호 등이 `***`로 보이는 것은 정상 동작입니다.
- **마스킹을 끄려면** `NoOpLoggingValueSanitizer`를 빈으로 등록:
  ```java
  @Bean
  LoggingValueSanitizer loggingValueSanitizer() {
      return new NoOpLoggingValueSanitizer();
  }
  ```
- **마스킹 패턴을 바꾸려면** `LoggingValueSanitizer`를 직접 구현해 빈으로 등록.

### 동작 변화 정리
| 변경 | 영향 | 대응 |
|------|------|------|
| `clear()` 키 추적 | 외부 MDC 키가 더 이상 라이브러리에 의해 지워지지 않음 (개선) | 없음 |
| query/userAgent 마스킹 | 로그 PII가 마스킹됨 | 원치 않으면 `NoOpLoggingValueSanitizer` |
| query URL 디코딩 | 인코딩된 쿼리가 평문으로 기록 | 없음 |
| X-Request-Id 응답 회신 | 응답 헤더 추가 | 원치 않으면 `return-trace-id-header: false` |

## 6. 검증 (테스트)

| 테스트 | 검증 |
|--------|------|
| `WebMdcContextAccessorTest` (키 누수 방지) | 외부 키 보존, owned 키만 제거, 스레드 재사용 누수 없음 |
| `DefaultPiiMaskingSanitizerTest` | 이메일/폰/주민/카드/Bearer 마스킹 + 경계 케이스 |
| `MdcRequestFilterTest` | userAgent 저장/truncate, query 디코딩/마스킹, X-Request-Id 회신/토글 |

## 7. 후속 (v1.7.0 예정)

- R4: 응답 메트릭(`status`/`durationMs`, `include-response-metrics` 토글, 기본 off)
- R6: `exclude-patterns`(`/actuator/**`) — MDC 필터 제외 경로
