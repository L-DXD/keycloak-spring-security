# 이슈: [Core] TokenInfo -> Principal 변환 매퍼 구현

## 🎯 목표
Keycloak에서 제공하는 TokenInfo 객체를 Spring Security의 Principal 객체로 변환하는 매퍼를 구현합니다. 
이를 통해 Keycloak 인증 정보를 Spring Security 컨텍스트에서 효과적으로 활용할 수 있도록 합니다.

## 📋 작업 상세 내용

### 1. TokenInfo 구조 분석
- `keycloak-spring-security-core` 모듈 내의 `TokenInfo` 또는 관련 클래스 구조를 분석합니다.
- `TokenInfo` 객체가 포함하는 클레임(Claim) 정보(예: `sub`, `preferred_username`, `email`, `roles` 등)를 파악합니다.

### 2. Principal 인터페이스 또는 클래스 정의/선택
- Spring Security에서 Keycloak 인증 정보를 표현하기에 가장 적합한 Principal 타입(예: `Authentication`, `JwtAuthenticationToken` 또는 커스텀 Principal)을 결정합니다.
- 필요한 경우 커스텀 Principal 클래스를 정의하고 포함할 속성을 결정합니다.

### 3. 변환 매퍼 인터페이스 및 구현
- `TokenInfo`를 결정된 Principal 타입으로 변환하는 매퍼 인터페이스(예: `TokenInfoToPrincipalMapper`)를 정의합니다.
- 인터페이스의 구현 클래스를 작성하고 `TokenInfo`의 클레임 정보를 Principal 객체로 매핑하는 로직을 구현합니다.
- 역할(Roles) 정보 매핑 방식(예: Keycloak의 `realm_access.roles` 또는 `resource_access.<client_id>.roles`를 Spring Security의 `GrantedAuthority`로 변환)을 결정하고 구현합니다.

### 4. 통합 및 활용 방안
- 구현된 매퍼를 Keycloak 인증 처리 흐름에 통합하는 방안을 고려합니다.
- Spring Security 컨텍스트에 Principal 객체를 설정하는 방법을 계획합니다.

### 5. 테스트
- 변환 매퍼의 단위 테스트를 작성하여 올바른 정보 매핑을 검증합니다.
- 다양한 `TokenInfo` 클레임 시나리오(예: 역할 유무, 특정 클레임 누락)에 대한 테스트 케이스를 포함합니다.

## ✅ 인수 조건
- [ ] `TokenInfoToPrincipalMapper` 인터페이스 및 구현 클래스가 정의된다.
- [ ] `TokenInfo`의 핵심 클레임(예: `sub`, `preferred_username`, `email`)이 Principal 객체로 올바르게 매핑된다.
- [ ] Keycloak의 역할 정보가 Spring Security의 `GrantedAuthority` 컬렉션으로 올바르게 변환되어 Principal에 포함된다.
- [ ] 매퍼에 대한 단위 테스트가 존재하며 모든 테스트를 통과한다.
