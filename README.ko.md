# keycloak-spring-security

[English](README.md) | **한국어**

Spring Boot 앱에 Keycloak 로그인을 붙이는 라이브러리입니다. 스타터 하나와 설정 몇 줄이면 브라우저 화면용 로그인·요청 인증·토큰 갱신·로그아웃이 켜집니다.

- **3.x**: Java 17+, Spring Boot 4.1, Spring Security 7.1, Servlet(Spring MVC). WebFlux는 3.1.0
- **방식**: 앱이 토큰을 맡는 BFF. 화면은 `__Host-` 쿠키만 들고, 액세스 토큰은 앱 안에서 검증하고(요청마다 Keycloak·DB를 부르지 않음), 리프레시 토큰은 앱 DB에 암호화해 둡니다
- **2.x**(Spring Boot 3.5)는 [docs/v2](docs/v2/GUIDE.ko.md)와 `2.x` 브랜치에 있습니다

## 문서

| 문서 | 내용 |
|---|---|
| [사용 가이드](docs/GUIDE.ko.md) | 빠른 시작, 동작 방식, 설정, 기능별 안내, 바꿔 끼우기, 문제 해결 |
| [v2 → v3 옮기기](docs/MIGRATION-v3.ko.md) | 바뀐 설정 키, 빠진 기능과 대안, DB 스키마, Keycloak client 설정 |
| [CHANGELOG](CHANGELOG.md) | 판마다 바뀐 것 |
| [SECURITY](SECURITY.ko.md) | 지원 판, 취약점 신고 |
| [docs/v3](docs/v3/README.md) | 설계, 수용 조건 시나리오, 검증 환경, 결정 기록 (기여자용) |

## 빠른 시작

```gradle
implementation("io.github.l-dxd:keycloak-spring-security-web-starter:3.0.0")
```

```yaml
spring.security.oauth2.client:
  registration.keycloak: { client-id: myapp, client-secret: ${KEYCLOAK_CLIENT_SECRET}, scope: openid }
  provider.keycloak.issuer-uri: https://sso.example.com/realms/my-realm

keycloak:
  security:
    frontend:
      base-url: https://app.example.com
    crypto:
      active-key-id: k1
      keys:
        k1: ${KSS_KEY_K1}            # openssl rand -base64 32
```

세션 테이블(`auth_session`)과 Keycloak client 설정은 [사용 가이드 1절](docs/GUIDE.ko.md#1-빠른-시작)을 따릅니다.

## 컨셉

1. **커스텀은 열어 둔다.** 자동 설정의 빈은 모두 `@ConditionalOnMissingBean`이라 같은 타입의 빈을 올리면 그것을 씁니다.
2. **`Customizer<T>`로 덧붙인다.** `KeycloakHttpConfigurer`는 로그인·CSRF·CORS·로그아웃 `Customizer`를 라이브러리 설정 뒤에 부릅니다.
3. **`final`을 쓰지 않는다.** 암호 도구(`SessionIds`, `Hkdf`)만 예외입니다. 처리기는 보호 메서드를 덮어써 바꿉니다.
4. **core와 구현, 스타터를 나눈다.** core는 Servlet·Spring Web을 모릅니다(ArchUnit으로 검사).
5. **스타터 하나와 설정 몇 줄.** 기본 보안 체인이 같이 올라오고, 앱이 다른 체인을 더해도 빠지지 않습니다.

## 모듈

| 모듈 (artifactId) | 담는 것 |
|---|---|
| `keycloak-spring-security-core` | 설정 값, 세션 저장소(JDBC·메모리, 스키마 SQL), 암호, 토큰 검증 규칙, 오류 코드, 세션 이벤트, MDC 키 |
| `keycloak-spring-security-web` | Servlet 필터와 처리기, `KeycloakHttpConfigurer` |
| `keycloak-spring-security-web-starter` | 자동 설정, `keycloak.security.*` 바인딩, 기동 검사 |

groupId는 `io.github.l-dxd`, 패키지 루트는 `com.ids.keycloak.security`입니다.

## 빌드와 검증

```bash
./gradlew build                                   # 단위·통합 테스트, 금지 의존성 검사, ArchUnit
./gradlew :integration-tests:servlet-app:e2eTest  # 샘플 앱 + 실제 Keycloak + PostgreSQL (Docker 또는 KSS_E2E_*)
```

E2E는 `integration-tests/servlet-app`의 샘플 Spring Boot 앱을 실제 Keycloak과 PostgreSQL에 붙여 로그인부터 back-channel 로그아웃까지 브라우저처럼 돌립니다. 돌리는 법은 [검증 환경](docs/v3/03-검증-환경.md)에 있습니다.

## 기여

이슈 하나에 PR 하나입니다. 이슈 본문의 수용 조건 시나리오가 테스트 이름이 되고, 모두 자동 테스트로 통과해야 닫습니다. 진행 방식은 [docs/v3/README](docs/v3/README.md)에 있습니다.

## 라이선스

[LICENSE](LICENSE.md)
