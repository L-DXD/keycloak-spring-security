# feat: Redis 세션 저장소 지원 추가

## 🎯 변경 내용 요약
`docs/07-redis-세션-저장소.md`에 기술된 계획에 따라 **Redis 세션 저장소**를 지원하도록 기능을 확장합니다.

기존 `IndexedMapSessionRepository`를 통한 In-Memory 방식 외에, `application.yml` 설정을 통해 Redis를 세션 저장소로 선택할 수 있게 하여 **다중 인스턴스 환경에서의 세션 공유 및 영속성**을 지원합니다.

주요 변경 사항:
1. **설정 주도 구성**: `keycloak.session.store-type` (MEMORY/REDIS) 프로퍼티를 통해 저장소를 선택할 수 있습니다.
2. **Redis 연결 위임**: 라이브러리 내부에서 Redis 연결을 직접 관리하지 않고, Spring Boot의 표준 `RedisAutoConfiguration`에 위임하여 Standalone, Sentinel, Cluster 등 다양한 구성을 지원합니다.
3. **호환성 유지**: `FindByIndexNameSessionRepository` 인터페이스를 통해 기존 백채널 로그아웃 기능이 Redis 환경에서도 동일하게 동작하도록 구현했습니다.

---

## ✅ 관련 이슈
<!-- 이 Pull Request가 해결하거나 관련된 이슈 번호를 여기에 작성해주세요. (예: #123) -->
- # (관련 이슈 번호를 입력해주세요)

---

## ✒️ 변경 유형
- [x] ✨ feat (새로운 기능)
- [ ] 🐛 fix (버그 수정)
- [x] 📝 docs (문서 추가 또는 수정)
- [x] ♻️ refactor (코드 리팩토링)
- [ ] 🎨 style (코드 형식, 세미콜론 추가 등)
- [x] 🔨 chore (빌드 관련 변경, 패키지 매니저 설정 등)
- [ ] 🧪 test (테스트 코드 추가 또는 수정)

---

## ✔️ 체크리스트
- [x] 코드 스타일 가이드라인을 준수했나요?
- [x] 새로운 테스트 코드를 추가했나요?
- [x] 기존 테스트가 모두 통과됐나요?
- [x] 관련 문서를 수정했나요?
- [x] 새로운 의존성을 추가했나요? (`compileOnly`로 선택적 의존성 추가)

---

## 💬 특이 사항 또는 리뷰 요청 사항
### 1. 의존성 관리
Redis 및 Spring Session 관련 의존성은 `compileOnly`로 선언하여, Redis를 사용하지 않는 사용자에게 불필요한 의존성이 추가되지 않도록 했습니다.

### 2. 제네릭 타입 변경
`OidcBackChannelSessionLogoutHandler`에서 기존 `MapSession` 구체 클래스에 의존하던 부분을 `Session` 인터페이스 및 와일드카드(`? extends Session`)로 변경하여 확장성을 확보했습니다.

### 3. AutoConfiguration 분리
`SessionConfiguration`을 `MemorySessionConfiguration`과 `RedisSessionConfiguration`으로 분리하고 `@ConditionalOnProperty`를 적용하여 선택된 저장소 유형에 맞는 Bean만 등록되도록 리팩토링했습니다.
