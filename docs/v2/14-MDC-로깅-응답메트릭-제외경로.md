# 14. MDC 로깅 — 응답 메트릭 · 제외 경로 · 호환성 정책 (v1.7.0)

> v1.6.0([13](13-MDC-로깅-사내표준-위임.md))에 이어 MDC 로깅 사내표준 위임을 마무리합니다.
> 요구사항 R4(응답 메트릭) · R6(제외 경로) · R7(호환성 정책).

## 1. 변경 요약

| 항목 | 내용 |
|------|------|
| **R4** | 요청 종료 시 `status`/`durationMs` MDC + `"request completed"` 종료 로그 (토글, **기본 off**) |
| **R6** | `exclude-patterns`(기본 `/actuator/**`)로 MDC 필터 제외 — `shouldNotFilter` + AntPathMatcher |
| **R7** | MDC 키 호환성 정책 문서화 |

## 2. R4 — 응답 메트릭 (status / durationMs)

`MdcRequestFilter`가 요청 종료 시점(finally)에 응답 상태와 처리 시간을 MDC에 넣고 종료 로그를 남깁니다.

```yaml
keycloak:
  security:
    logging:
      include-response-metrics: false   # 기본 off
```

- 켜면 JSON 비즈니스 로그 한 줄(`"request completed"`)에 `status`/`durationMs`가 MDC 전체(traceId·userId 등)와 함께 묶여, Loki에서 조인 없이 요청 단위 추적이 됩니다.
- **기본 off인 이유**: 모든 요청에 종료 로그 1줄이 추가되고 Tomcat AccessLog와 정보가 중복됩니다. AccessLog를 쓰지 않거나 로그를 일원화하려는 환경에서만 켜세요.

| 키 | 값 | 세팅 시점 |
|----|----|----------|
| `status` | HTTP 응답 상태 코드 | 요청 종료 |
| `durationMs` | 처리 소요 시간(ms) | 요청 종료 |

## 3. R6 — 제외 경로 (shouldNotFilter)

```yaml
keycloak:
  security:
    logging:
      exclude-patterns:
        - /actuator/**     # 기본값
```

- `MdcRequestFilter.shouldNotFilter()`가 `AntPathMatcher`로 매칭하여 해당 경로는 MDC 필터를 통과하지 않습니다.
- actuator 헬스/메트릭 스크랩(Prometheus 폴링)의 요청 로그 노이즈를 제거합니다.
- 빈 리스트로 두면 모든 경로에 필터를 적용합니다.

## 4. R7 — MDC 키 호환성 정책

라이브러리가 노출하는 MDC 키(`LoggingContextKeys`)는 사내 표준 로그 스키마의 일부이므로 다음 버저닝 규칙을 따릅니다.

| 변경 | 허용 버전 | 비고 |
|------|----------|------|
| 새 키 **추가** | minor | 기존 로그 파이프라인 호환 |
| 키명 **변경/삭제** | major | Loki 쿼리·대시보드 영향 → breaking |
| 키 값 포맷 변경 | minor + 문서 명시 | 예: durationMs 단위 변경 |

- 키를 추가/변경할 때는 사내 로깅 표준 프로세스 문서의 MDC 키 표를 **동시에 갱신**합니다.
- 현재 키 목록: `traceId`, `httpMethod`, `requestUri`, `queryString`, `clientIp`, `userAgent`, `status`, `durationMs`, `userId`, `username`, `sessionId`

## 5. 신규 프로퍼티

```yaml
keycloak:
  security:
    logging:
      include-response-metrics: false   # status/durationMs + 종료 로그 (기본 off)
      exclude-patterns:                  # MDC 필터 제외 경로 (기본 [/actuator/**])
        - /actuator/**
```

## 6. 검증 (테스트)

| 테스트 | 검증 |
|--------|------|
| `MdcRequestFilterTest` (응답 메트릭 R4) | 토글 on 시 status/durationMs 저장, off 시 미저장 |
| `MdcRequestFilterTest` (제외 경로 R6) | `/actuator/**` 제외, 일반 경로 적용, 커스텀 패턴 |

## 7. MDC 로깅 표준 위임 — 완료

R1~R7 + X-Request-Id가 v1.6.0~v1.7.0으로 모두 반영되어, `keycloak-spring-security-web-starter`가 사내 로깅 표준의 MDC 단일 소유자로 동작합니다. 자체 `MdcLoggingFilter` 구현은 더 이상 필요하지 않습니다.
