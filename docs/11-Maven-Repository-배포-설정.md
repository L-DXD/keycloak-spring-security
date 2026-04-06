# Maven Repository 배포 설정

## 목표

`keycloak-spring-security` 라이브러리를 Maven Central에 배포합니다.

**배포 대상 (5개 모듈):**
- **core**: 공통 유틸리티 및 모델
- **web**: Servlet 기반 보안 구현
- **webflux**: Reactive 기반 보안 구현
- **web-starter**: Servlet 자동 설정
- **webflux-starter**: WebFlux 자동 설정

---

## 1. 프로젝트 구조 및 의존성

```
keycloak-spring-security/
├── core/                    # 공통 코어 (배포 O)
│     ↑
├── web/                     # Servlet 기반 (배포 O)
│     ↑
├── web-starter/             # Servlet 자동 설정 (배포 O)
│
├── core/                    # (공유)
│     ↑
├── webflux/                 # WebFlux 기반 (배포 O)
│     ↑
├── webflux-starter/         # WebFlux 자동 설정 (배포 O)
│
└── integration-tests/       # 테스트 (배포 제외)
```

### 버전 관리 전략

**단일 버전 관리** - 모든 모듈이 동일한 버전으로 배포됩니다.

| 버전 변수 | 적용 모듈 | 태그 패턴 |
|-----------|-----------|-----------|
| `projectVersion` | 모든 모듈 | `v*` |

---

## 2. 사용 플러그인: vanniktech maven-publish

`com.vanniktech.maven.publish` 플러그인을 사용합니다.

### 장점
| 항목 | vanniktech 플러그인 | 기본 maven-publish |
|------|---------------------|-------------------|
| 설정 복잡도 | 낮음 | 높음 |
| source/javadoc jar | 자동 생성 | 수동 설정 필요 |
| Sonatype Central Portal | 직접 지원 | 별도 설정 필요 |
| 서명 | `signAllPublications()` 한 줄 | signing 블록 상세 설정 |
| project() 참조 | 자동으로 Maven 좌표 변환 | 수동 설정 필요 |

### Sonatype Central Portal
2024년 3월부터 **새 프로젝트는 Central Portal 사용 필수** (기존 OSSRH 신규 등록 불가)
- `SonatypeHost.CENTRAL_PORTAL` 사용

---

## 3. 확정 사항

| 항목 | 값 |
|------|-----|
| **groupId** | `io.github.l-dxd` |
| **라이선스** | MIT License |
| **개발자** | LeeBongSeung |

---

## 4. 구현 설정

### 4.1 gradle.properties

```properties
# gradle.properties

# 버전 관리 (단일 버전)
projectVersion=0.0.2

# Maven 배포 정보
mavenGroupId=io.github.l-dxd
mavenProjectUrl=https://github.com/L-DXD/keycloak-spring-security
mavenScmUrl=github.com/L-DXD/keycloak-spring-security.git

# 개발자 정보
developerId=LeeBongSeung
developerName=LeeBongSeung
developerUrl=https://github.com/L-DXD/keycloak-spring-security
```

---

### 4.2 루트 build.gradle

```groovy
plugins {
    id 'io.spring.dependency-management' version '1.1.5' apply false
    id 'com.vanniktech.maven.publish' version '0.28.0' apply false
}

println "=================================================="
println "  Building Keycloak Spring Security Library"
println "  Version: ${projectVersion}"
println "=================================================="

allprojects {
    group = mavenGroupId

    repositories {
        mavenCentral()
    }
}

subprojects {
    plugins.withType(JavaPlugin) {
        java {
            sourceCompatibility = JavaVersion.VERSION_17
            targetCompatibility = JavaVersion.VERSION_17
        }

        tasks.withType(Test) {
            useJUnitPlatform()
        }

        tasks.withType(Javadoc) {
            options {
                encoding 'UTF-8'
            }
        }
    }

    plugins.withId('io.spring.dependency-management') {
        dependencyManagement {
            imports {
                mavenBom "org.springframework.boot:spring-boot-dependencies:3.5.9"
            }
        }
    }

    afterEvaluate { project ->
        if (project.plugins.hasPlugin(JavaPlugin)) {
            project.dependencies {
                testImplementation 'org.junit.jupiter:junit-jupiter-api'
                testRuntimeOnly 'org.junit.jupiter:junit-jupiter-engine'
                testImplementation 'org.assertj:assertj-core'
                testImplementation 'org.mockito:mockito-core'
                testImplementation 'org.mockito:mockito-junit-jupiter'
                testRuntimeOnly 'org.junit.platform:junit-platform-launcher'
                compileOnly 'org.projectlombok:lombok'
                annotationProcessor 'org.projectlombok:lombok'
                implementation 'org.slf4j:slf4j-api'
                implementation 'io.github.l-dxd:keycloak-client:1.0.0'
            }
        }
    }
}
```

---

### 4.3 모듈별 build.gradle

#### keycloak-spring-security-core/build.gradle
```groovy
import com.vanniktech.maven.publish.SonatypeHost

plugins {
    id 'java-library'
    id 'io.spring.dependency-management'
    id 'com.vanniktech.maven.publish'
    id 'signing'
}

version = projectVersion
description = 'Keycloak Spring Security Core - Common utilities and models'

dependencies {
    api 'org.springframework.security:spring-security-core'
    api 'org.springframework.boot:spring-boot-starter-oauth2-resource-server'
    implementation 'com.fasterxml.jackson.core:jackson-annotations'
}

signing {
    def secretFile = file("${rootDir}/secret.asc")
    def signingPassword = findProperty("signingInMemoryKeyPassword")
        ?: findProperty("signing.password")

    if (secretFile.exists()) {
        def signingKey = secretFile.text
        useInMemoryPgpKeys(signingKey, signingPassword as String)
        sign publishing.publications
    }
}

mavenPublishing {
    publishToMavenCentral(SonatypeHost.CENTRAL_PORTAL)
    signAllPublications()

    coordinates(mavenGroupId, "keycloak-spring-security-core", version as String)

    pom {
        name = "keycloak-spring-security-core"
        description = project.description
        inceptionYear = "2025"
        url = mavenProjectUrl

        licenses {
            license {
                name = "MIT License"
                url = "https://opensource.org/licenses/MIT"
                distribution = "repo"
            }
        }

        developers {
            developer {
                id = developerId
                name = developerName
                url = developerUrl
            }
        }

        scm {
            url = mavenProjectUrl
            connection = "scm:git:git://${mavenScmUrl}"
            developerConnection = "scm:git:ssh://git@${mavenScmUrl}"
        }
    }
}
```

#### keycloak-spring-security-web/build.gradle
```groovy
import com.vanniktech.maven.publish.SonatypeHost

plugins {
    id 'java-library'
    id 'io.spring.dependency-management'
    id 'com.vanniktech.maven.publish'
    id 'signing'
}

version = projectVersion
description = 'Keycloak Spring Security Web - Servlet-based security implementation'

dependencies {
    // Core 모듈에 의존 (배포 시 자동으로 Maven 좌표로 변환됨)
    api project(':keycloak-spring-security-core')

    api 'org.springframework.session:spring-session-core'
    api 'org.springframework.security:spring-security-web'
    api 'org.springframework.security:spring-security-config'
    api 'org.springframework.security:spring-security-oauth2-client'
    api 'org.springframework.security:spring-security-oauth2-jose'
    compileOnly 'jakarta.servlet:jakarta.servlet-api'
    implementation 'com.fasterxml.jackson.core:jackson-databind'
}

// signing, mavenPublishing 블록은 core와 동일 (coordinates만 변경)
// coordinates(mavenGroupId, "keycloak-spring-security-web", version as String)
```

#### keycloak-spring-security-webflux/build.gradle
```groovy
// web과 동일한 구조
// coordinates(mavenGroupId, "keycloak-spring-security-webflux", version as String)
dependencies {
    api project(':keycloak-spring-security-core')
    api 'org.springframework.boot:spring-boot-starter-webflux'
    implementation 'org.springframework.boot:spring-boot-starter-security'
    implementation 'com.fasterxml.jackson.core:jackson-databind'
}
```

#### keycloak-spring-security-web-starter/build.gradle
```groovy
// starter 모듈
// coordinates(mavenGroupId, "keycloak-spring-security-web-starter", version as String)
dependencies {
    api 'org.springframework.boot:spring-boot-autoconfigure'
    api 'org.springframework.session:spring-session-core'
    annotationProcessor 'org.springframework.boot:spring-boot-configuration-processor'

    // Web 모듈에 의존 (배포 시 자동으로 Maven 좌표로 변환됨)
    api project(':keycloak-spring-security-web')

    compileOnly 'org.springframework.boot:spring-boot-starter-web'
}
```

#### keycloak-spring-security-webflux-starter/build.gradle
```groovy
// starter 모듈
// coordinates(mavenGroupId, "keycloak-spring-security-webflux-starter", version as String)
dependencies {
    api 'org.springframework.boot:spring-boot-autoconfigure'
    annotationProcessor 'org.springframework.boot:spring-boot-configuration-processor'

    // WebFlux 모듈에 의존 (배포 시 자동으로 Maven 좌표로 변환됨)
    api project(':keycloak-spring-security-webflux')

    compileOnly 'org.springframework.boot:spring-boot-starter-webflux'
}
```

---

### 4.4 GPG 서명 설정

#### GPG 키 생성
```bash
# GPG 키 생성
gpg --full-generate-key

# 키 ID 확인
gpg --list-secret-keys --keyid-format LONG

# 공개키 서버에 업로드 (Maven Central 검증용)
gpg --keyserver keyserver.ubuntu.com --send-keys YOUR_KEY_ID
```

#### secret.asc 파일 생성
```bash
# 비밀키 내보내기 (-----BEGIN 부분 제외)
gpg --armor --export-secret-keys YOUR_KEY_ID > temp.asc

# temp.asc 파일에서 "-----BEGIN PGP PRIVATE KEY BLOCK-----" 이후 내용만 secret.asc로 저장
# 즉, "IN PGP PRIVATE KEY BLOCK-----" 부터 시작
```

**주의:** `secret.asc`와 `gradle.properties`의 signing.password는 `.gitignore`에 추가

```gitignore
# .gitignore
secret.asc
```

---

## 5. CI/CD 파이프라인 (GitHub Actions)

### 5.1 릴리스 워크플로우

```yaml
# .github/workflows/publish.yml
name: Publish to Maven Central

permissions:
  contents: write

on:
  push:
    tags:
      - 'v*'

  workflow_dispatch:

jobs:
  publish:
    name: Publish All Modules to Maven Central
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up JDK 17
        uses: actions/setup-java@v4
        with:
          java-version: '17'
          distribution: 'temurin'

      - name: Setup Gradle
        uses: gradle/actions/setup-gradle@v3

      - name: Grant execute permission
        run: chmod +x ./gradlew

      - name: Decode GPG Key
        run: |
          echo "${{ secrets.GPG_SECRET_KEY_BASE64 }}" | base64 --decode > secret.asc
          echo "ORG_GRADLE_PROJECT_signingInMemoryKey<<EOF" >> $GITHUB_ENV
          cat secret.asc >> $GITHUB_ENV
          echo "EOF" >> $GITHUB_ENV

      - name: Build all modules
        run: ./gradlew build --no-daemon

      # 배포 순서: core → web, webflux → web-starter, webflux-starter
      - name: Publish core
        run: ./gradlew :keycloak-spring-security-core:publish --no-daemon
        env:
          ORG_GRADLE_PROJECT_mavenCentralUsername: ${{ secrets.MAVEN_CENTRAL_USERNAME }}
          ORG_GRADLE_PROJECT_mavenCentralPassword: ${{ secrets.MAVEN_CENTRAL_PASSWORD }}
          ORG_GRADLE_PROJECT_signingInMemoryKeyPassword: ${{ secrets.GPG_PASSWORD }}

      - name: Publish web and webflux
        run: |
          ./gradlew :keycloak-spring-security-web:publish --no-daemon
          ./gradlew :keycloak-spring-security-webflux:publish --no-daemon
        env:
          ORG_GRADLE_PROJECT_mavenCentralUsername: ${{ secrets.MAVEN_CENTRAL_USERNAME }}
          ORG_GRADLE_PROJECT_mavenCentralPassword: ${{ secrets.MAVEN_CENTRAL_PASSWORD }}
          ORG_GRADLE_PROJECT_signingInMemoryKeyPassword: ${{ secrets.GPG_PASSWORD }}

      - name: Publish web-starter and webflux-starter
        run: |
          ./gradlew :keycloak-spring-security-web-starter:publish --no-daemon
          ./gradlew :keycloak-spring-security-webflux-starter:publish --no-daemon
        env:
          ORG_GRADLE_PROJECT_mavenCentralUsername: ${{ secrets.MAVEN_CENTRAL_USERNAME }}
          ORG_GRADLE_PROJECT_mavenCentralPassword: ${{ secrets.MAVEN_CENTRAL_PASSWORD }}
          ORG_GRADLE_PROJECT_signingInMemoryKeyPassword: ${{ secrets.GPG_PASSWORD }}

      - name: Clean up
        if: always()
        run: rm -f secret.asc
```

### 5.2 GitHub Secrets 설정

**설정 경로:** `Repository` → `Settings` → `Secrets and variables` → `Actions` → `New repository secret`

| Secret 이름 | 설명 |
|-------------|------|
| `MAVEN_CENTRAL_USERNAME` | Sonatype Central Portal 사용자명 |
| `MAVEN_CENTRAL_PASSWORD` | Sonatype Central Portal 토큰 |
| `GPG_SECRET_KEY_BASE64` | GPG 비밀키 (Base64 인코딩) |
| `GPG_PASSWORD` | GPG 키 비밀번호 |

---

## 6. 릴리스 절차

### 6.1 버전 업데이트 및 배포

```bash
# 1. gradle.properties에서 projectVersion 업데이트
projectVersion=0.0.3

# 2. 커밋 & 푸시
git add gradle.properties
git commit -m "chore: bump version to 0.0.3"
git push

# 3. 태그 생성 -> CI 자동 배포 (모든 모듈)
git tag v0.0.3
git push origin v0.0.3
```

---

## 7. 로컬 테스트 (배포 전 검증)

### 7.1 publishToMavenLocal 실행

```bash
# 모든 모듈 로컬 배포 테스트
./gradlew publishToMavenLocal
```

### 7.2 결과 확인

```bash
# 아티팩트 목록 확인
ls ~/.m2/repository/io/github/l-dxd/

# 예상 결과:
# keycloak-spring-security-core/
# keycloak-spring-security-web/
# keycloak-spring-security-webflux/
# keycloak-spring-security-web-starter/
# keycloak-spring-security-webflux-starter/
```

**성공 시 각 모듈 폴더 내 파일:**
```
keycloak-spring-security-core-0.0.2.jar
keycloak-spring-security-core-0.0.2.jar.asc          ← 서명 파일
keycloak-spring-security-core-0.0.2.pom
keycloak-spring-security-core-0.0.2.pom.asc
keycloak-spring-security-core-0.0.2-sources.jar
keycloak-spring-security-core-0.0.2-javadoc.jar
```

---

## 8. 배포 후 확인

### 8.1 Maven Central 검색

배포 후 약 10-30분 후 검색 가능:
- https://central.sonatype.com/search?q=g:io.github.l-dxd

### 8.2 사용자 의존성 추가

```groovy
// Servlet 프로젝트 (권장)
implementation 'io.github.l-dxd:keycloak-spring-security-web-starter:0.0.2'

// WebFlux 프로젝트 (권장)
implementation 'io.github.l-dxd:keycloak-spring-security-webflux-starter:0.0.2'
```

```xml
<!-- Maven -->
<dependency>
    <groupId>io.github.l-dxd</groupId>
    <artifactId>keycloak-spring-security-web-starter</artifactId>
    <version>0.0.2</version>
</dependency>
```

---

## 9. 작업 체크리스트

### 초기 설정
- [x] `gradle.properties` 생성 (projectVersion 단일 버전)
- [x] 루트 `build.gradle` 수정

### 모듈별 설정
- [x] `keycloak-spring-security-core/build.gradle` 수정
- [x] `keycloak-spring-security-web/build.gradle` 수정
- [x] `keycloak-spring-security-webflux/build.gradle` 수정
- [x] `keycloak-spring-security-web-starter/build.gradle` 수정
- [x] `keycloak-spring-security-webflux-starter/build.gradle` 수정

### GPG 서명
- [ ] GPG 키 생성 (또는 기존 키 사용)
- [ ] 공개키 서버 업로드
- [ ] `secret.asc` 파일 생성
- [x] `.gitignore`에 `secret.asc` 추가

### CI/CD
- [x] `.github/workflows/publish.yml` 생성
- [ ] GitHub Secrets 설정

### 테스트 및 배포
- [ ] `./gradlew publishToMavenLocal` 로컬 테스트
- [ ] 태그 푸시로 CI/CD 배포

---

## 10. 요약

| 항목 | 값 |
|------|------|
| groupId | `io.github.l-dxd` |
| 버전 관리 | 단일 버전 (`projectVersion`) |
| 배포 대상 | core, web, webflux, web-starter, webflux-starter (5개) |
| 태그 패턴 | `v*` (예: v0.0.2) |
| 배포 순서 | core → web, webflux → web-starter, webflux-starter |
| 라이선스 | MIT License |
