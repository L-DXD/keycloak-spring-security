# integration-tests

v3 검증용 샘플 앱과 실제 Keycloak E2E. 배포하지 않는다.

| 폴더 | 내용 |
|---|---|
| `servlet-app/` | 샘플 Spring Boot 앱(가상 프로젝트)과 E2E 테스트(`src/test/.../e2e`) |
| `keycloak/realm-kss-demo.json` | 테스트 realm. client `demo`·`demo2`, 사용자 `alice`·`bob` (테스트 값) |
| `keycloak/start-local.sh` | Docker 없이 Keycloak 배포판을 `http://sso.kss.test:8180`에 띄운다 |
| `keycloak/gen-test-certs.sh` | 테스트 CA와 `api.kss.test` 인증서를 빌드 폴더에 만든다 |

```bash
./gradlew :integration-tests:servlet-app:e2eTest     # Docker가 있으면 이것만
```

Docker가 없을 때, 이름 풀기, 시나리오 목록은 [docs/v3/03-검증-환경.md](../docs/v3/03-검증-환경.md)와 [02-수용조건-시나리오.md](../docs/v3/02-수용조건-시나리오.md)에 있다.
