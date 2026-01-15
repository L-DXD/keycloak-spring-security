# Maven Repository 배포 설정

## 목표

`keycloak-spring-security` 라이브러리를 Maven Central에 배포합니다.
- **web-starter**: 배포 O
- **webflux-starter**: 배포 O
- **core, web, webflux**: 내부 모듈 (배포 제외)

---

## 1. 현재 상태 분석

### 프로젝트 구조 및 의존성
```
keycloak-spring-security/
├── core/                    # 공통 코어 (내부 모듈, 배포 제외)
│     ↑
├── web/                     # Servlet 기반 (내부 모듈, 배포 제외)
│     ↑
├── web-starter/             # Servlet 자동 설정 (배포 대상)
│
├── webflux/                 # WebFlux 기반 (내부 모듈, 배포 제외)
│     ↑
├── webflux-starter/         # WebFlux 자동 설정 (배포 대상)
│
└── integration-tests/       # 테스트 (배포 제외)
```

### 버전 관리 전략
| 버전 변수 | 적용 모듈 | 태그 패턴 | 배포 |
|-----------|-----------|-----------|------|
| `webVersion` | web-starter | `web-starter-v*` | O |
| `webfluxVersion` | webflux-starter | `webflux-starter-v*` | O |
| - | core, web, webflux | - | X (내부 모듈) |

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

## 4. 구현 계획

### Phase 1: gradle.properties 생성

```properties
# gradle.properties

# 버전 관리
webVersion=1.0.0
webfluxVersion=1.0.0

# Maven 배포 정보
mavenGroupId=io.github.l-dxd
mavenProjectUrl=https://github.com/L-DXD/keycloak-spring-security
mavenScmUrl=github.com/L-DXD/keycloak-spring-security.git

# 개발자 정보
developerId=LeeBongSeung
developerName=LeeBongSeung
developerUrl=https://github.com/L-DXD/keyclaok-spring-security

# 서명 비밀번호 (로컬 빌드용, CI에서는 환경변수 사용)
# signing.password=your-gpg-password
```

---

### Phase 2: 루트 build.gradle 수정

```groovy
plugins {
    id 'io.spring.dependency-management' version '1.1.5' apply false
    id 'com.vanniktech.maven.publish' version '0.28.0' apply false
}

println "=================================================="
println "  Building Keycloak Spring Security Library"
println "  Web Version: ${webVersion}"
println "  WebFlux Version: ${webfluxVersion}"
println "=================================================="

allprojects {
    group = mavenGroupId

    repositories {
        mavenCentral()
    }
}

subprojects {
    plugins.withId('java-base') {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17

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
        if (project.plugins.hasPlugin('java-base')) {
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

### Phase 3: Starter 모듈 build.gradle 수정

> **Note:** `core`, `web`, `webflux`는 배포 대상이 아니므로 기존 build.gradle 유지 (maven-publish 플러그인 불필요)

#### 3.1 keycloak-spring-security-web-starter/build.gradle
```groovy
import com.vanniktech.maven.publish.SonatypeHost

plugins {
    id 'java-library'
    id 'io.spring.dependency-management'
    id 'com.vanniktech.maven.publish'
    id 'signing'
}

version = webVersion
description = 'Keycloak Spring Security Web Starter - Auto-configuration for Servlet applications'

dependencies {
    api 'org.springframework.boot:spring-boot-autoconfigure'
    api 'org.springframework.session:spring-session-core'
    annotationProcessor 'org.springframework.boot:spring-boot-configuration-processor'
    api project(':keycloak-spring-security-web')
    compileOnly 'org.springframework.boot:spring-boot-starter-web'
}

signing {
    def secretFile = file("${rootDir}/secret.asc")
    def signingKey = secretFile.exists() ? secretFile.text : null

    if (signingKey != null) {
        useInMemoryPgpKeys(
                "-----BEG" + signingKey,
                findProperty("signing.password") as String
        )
        sign publishing.publications
    }
}

mavenPublishing {
    publishToMavenCentral(SonatypeHost.CENTRAL_PORTAL)
    signAllPublications()

    coordinates(mavenGroupId, "keycloak-spring-security-web-starter", version as String)

    pom {
        name = "keycloak-spring-security-web-starter"
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

#### 3.2 keycloak-spring-security-webflux-starter/build.gradle
```groovy
import com.vanniktech.maven.publish.SonatypeHost

plugins {
    id 'java-library'
    id 'io.spring.dependency-management'
    id 'com.vanniktech.maven.publish'
    id 'signing'
}

version = webfluxVersion
description = 'Keycloak Spring Security WebFlux Starter - Auto-configuration for Reactive applications'

dependencies {
    api 'org.springframework.boot:spring-boot-autoconfigure'
    annotationProcessor 'org.springframework.boot:spring-boot-configuration-processor'
    api project(':keycloak-spring-security-webflux')
    compileOnly 'org.springframework.boot:spring-boot-starter-webflux'
}

signing {
    def secretFile = file("${rootDir}/secret.asc")
    def signingKey = secretFile.exists() ? secretFile.text : null

    if (signingKey != null) {
        useInMemoryPgpKeys(
                "-----BEG" + signingKey,
                findProperty("signing.password") as String
        )
        sign publishing.publications
    }
}

mavenPublishing {
    publishToMavenCentral(SonatypeHost.CENTRAL_PORTAL)
    signAllPublications()

    coordinates(mavenGroupId, "keycloak-spring-security-webflux-starter", version as String)

    pom {
        name = "keycloak-spring-security-webflux-starter"
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

---

### Phase 4: GPG 서명 설정

#### 4.1 GPG 키 생성
```bash
# GPG 키 생성
gpg --full-generate-key

# 키 ID 확인
gpg --list-secret-keys --keyid-format LONG

# 공개키 서버에 업로드 (Maven Central 검증용)
gpg --keyserver keyserver.ubuntu.com --send-keys YOUR_KEY_ID
```

#### 4.2 secret.asc 파일 생성
```bash
# 비밀키 내보내기 (-----BEGIN 부분 제외)
gpg --armor --export-secret-keys YOUR_KEY_ID > temp.asc

# temp.asc 파일에서 "-----BEGIN PGP PRIVATE KEY BLOCK-----" 이후 내용만 secret.asc로 저장
# 즉, "IN PGP PRIVATE KEY BLOCK-----" 부터 시작
```

**주의:** `secret.asc`와 `gradle.properties`는 `.gitignore`에 추가하여 커밋되지 않도록 합니다.

```gitignore
# .gitignore
secret.asc
gradle.properties
```

#### 4.3 서명 비밀번호 설정
`gradle.properties` (로컬, 커밋 제외) 또는 환경변수:
```properties
signing.password=your-gpg-password
```

---

### Phase 5: CI/CD 파이프라인 (GitHub Actions)

#### 5.1 릴리스 워크플로우
```yaml
# .github/workflows/publish.yml
name: Publish to Maven Central

on:
  push:
    tags:
      - 'web-starter-v*'
      - 'webflux-starter-v*'

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up JDK 17
        uses: actions/setup-java@v4
        with:
          java-version: '17'
          distribution: 'temurin'

      - name: Setup Gradle
        uses: gradle/actions/setup-gradle@v3

      - name: Create secret.asc
        run: echo "${{ secrets.GPG_SECRET_KEY }}" > secret.asc

      - name: Determine module to publish
        id: module
        run: |
          TAG=${GITHUB_REF#refs/tags/}
          if [[ $TAG == web-starter-v* ]]; then
            echo "task=:keycloak-spring-security-web-starter:publish" >> $GITHUB_OUTPUT
            echo "name=web-starter" >> $GITHUB_OUTPUT
          elif [[ $TAG == webflux-starter-v* ]]; then
            echo "task=:keycloak-spring-security-webflux-starter:publish" >> $GITHUB_OUTPUT
            echo "name=webflux-starter" >> $GITHUB_OUTPUT
          fi

      - name: Publish ${{ steps.module.outputs.name }} to Maven Central
        run: ./gradlew ${{ steps.module.outputs.task }}
        env:
          ORG_GRADLE_PROJECT_mavenCentralUsername: ${{ secrets.MAVEN_CENTRAL_USERNAME }}
          ORG_GRADLE_PROJECT_mavenCentralPassword: ${{ secrets.MAVEN_CENTRAL_PASSWORD }}
          ORG_GRADLE_PROJECT_signing.password: ${{ secrets.GPG_PASSWORD }}
```

#### 5.2 GitHub Secrets 설정

**설정 경로:** `Repository` → `Settings` → `Secrets and variables` → `Actions` → `New repository secret`

| Secret 이름 | 설명 | 값 획득 방법 |
|-------------|------|-------------|
| `MAVEN_CENTRAL_USERNAME` | Sonatype Central Portal 사용자명 | [central.sonatype.com](https://central.sonatype.com) → 로그인 → 우측 상단 계정 메뉴 → `View Account` → Username |
| `MAVEN_CENTRAL_PASSWORD` | Sonatype Central Portal 토큰 | [central.sonatype.com](https://central.sonatype.com) → `View Account` → `Generate User Token` → Password 값 |
| `GPG_SECRET_KEY` | GPG 비밀키 (secret.asc 내용) | `gpg --armor --export-secret-keys KEY_ID` 실행 후 `-----BEGIN` 이후 전체 내용 |
| `GPG_PASSWORD` | GPG 키 생성 시 설정한 비밀번호 | GPG 키 생성 시 입력한 passphrase |

> **참고:** `GITHUB_TOKEN`은 자동 제공되므로 별도 설정 불필요

---

### Phase 6: 릴리스 절차

#### 6.1 web-starter 릴리스
```bash
# 1. gradle.properties에서 webVersion 업데이트
webVersion=1.1.0

# 2. 커밋 & 푸시
git add gradle.properties
git commit -m "chore: bump web-starter version to 1.1.0"
git push

# 3. 태그 생성 -> CI 자동 배포
git tag web-starter-v1.1.0
git push origin web-starter-v1.1.0
```

#### 6.2 webflux-starter 릴리스
```bash
# 1. gradle.properties에서 webfluxVersion 업데이트
webfluxVersion=1.1.0

# 2. 커밋 & 푸시
git add gradle.properties
git commit -m "chore: bump webflux-starter version to 1.1.0"
git push

# 3. 태그 생성 -> CI 자동 배포
git tag webflux-starter-v1.1.0
git push origin webflux-starter-v1.1.0
```

---

## 5. 사전 준비 사항

### 5.1 Sonatype Central Portal 계정
1. https://central.sonatype.com 에서 계정 생성
2. Namespace 등록: `io.github.l-dxd`
   - GitHub 기반이므로 GitHub 프로필에서 자동 검증

### 5.2 이미 등록된 Namespace 확인
`io.github.l-dxd`가 이미 `keycloak-client` 배포에 사용 중이라면 추가 등록 불필요

---

## 6. 배포 후 확인

### 6.1 Maven Central 검색
배포 후 약 10-30분 후 검색 가능:
- https://central.sonatype.com/search?q=g:io.github.l-dxd

### 6.2 사용자 의존성 추가
```groovy
// Servlet 프로젝트
implementation 'io.github.l-dxd:keycloak-spring-security-web-starter:1.0.0'

// WebFlux 프로젝트
implementation 'io.github.l-dxd:keycloak-spring-security-webflux-starter:1.0.0'
```

---

## 7. 작업 체크리스트

### Phase 1: 버전 관리
- [x] `gradle.properties` 생성
- [x] 루트 `build.gradle` 수정

### Phase 2: 모듈별 설정
- [x] `keycloak-spring-security-web-starter/build.gradle` 수정
- [x] `keycloak-spring-security-webflux-starter/build.gradle` 수정

### Phase 3: GPG 서명
- [ ] GPG 키 생성 (또는 기존 키 사용)
- [ ] 공개키 서버 업로드
- [ ] `secret.asc` 파일 생성
- [x] `.gitignore`에 `secret.asc` 추가

### Phase 4: CI/CD
- [x] `.github/workflows/publish.yml` 생성
- [ ] GitHub Secrets 설정

### Phase 5: 검증
- [ ] `./gradlew publishToMavenLocal` 로컬 테스트
- [ ] 실제 배포 테스트

---

## 8. 결정 완료 사항

| 항목 | 결정 |
|------|------|
| groupId | `io.github.l-dxd` |
| 배포 대상 | web-starter, webflux-starter만 |
| 배포 제외 | core, web, webflux (내부 모듈) |
| 라이선스 | MIT License |
| 개발자 | LeeBongSeung |
