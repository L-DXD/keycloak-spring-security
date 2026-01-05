# 이슈: Gradle 멀티 모듈 구조 초기화

## 🎯 목표

`README.md`에 정의된 가이드라인에 따라 프로젝트의 초기 Gradle 멀티 모듈 구조를 설정합니다.
루트 프로젝트와 5개의 라이브러리 서브 모듈(`core`, `servlet`, `reactive`, `servlet-starter`, `reactive-starter`)이 정상적으로 인식되고 빌드되는 환경을 구축합니다.

## 📋 작업 상세 내용

### 1. 루트 프로젝트 설정
- `settings.gradle`에 하위 모듈 include 설정
- `build.gradle`에 공통 플러그인(Java, Spring Boot, Dependency Management) 및 버전 변수 설정

### 2. 서브 모듈 디렉터리 및 빌드 파일 생성
각 모듈별로 디렉터리를 생성하고, 독립적인 `build.gradle` 파일을 초기화합니다.
- **Target Modules:**
  - `keycloak-spring-security-core`
  - `keycloak-spring-security-servlet`
  - `keycloak-spring-security-reactive`
  - `keycloak-spring-security-servlet-starter`
  - `keycloak-spring-security-reactive-starter`

## ✅ 인수 조건 (Acceptance Criteria)
- [x] `./gradlew clean build` 실행 시 실패 없이 모든 모듈이 빌드되어야 한다.
- [x] IntelliJ/Eclipse 등 IDE에서 Gradle 프로젝트 로드 시 4개의 모듈이 계층 구조로 올바르게 인식되어야 한다.