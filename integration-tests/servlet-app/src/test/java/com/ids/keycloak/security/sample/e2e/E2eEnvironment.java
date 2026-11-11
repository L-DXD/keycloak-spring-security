package com.ids.keycloak.security.sample.e2e;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Objects;

import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

/**
 * E2E에 쓰는 Keycloak과 PostgreSQL (docs/v3/03-검증-환경.md 3절).
 * <ul>
 *   <li>E2E-01: 환경 변수가 없으면 Testcontainers로 띄운다 (Docker 필요)</li>
 *   <li>E2E-02: {@code KSS_E2E_KEYCLOAK_URL}, {@code KSS_E2E_DB_URL}을 주면 밖에 띄운 것을 쓴다
 *       ({@code integration-tests/keycloak/start-local.sh})</li>
 * </ul>
 * JVM 하나에 한 번만 띄우고, JVM이 끝날 때 컨테이너를 내린다.
 */
public final class E2eEnvironment {

    public static final String REALM = "kss-demo";
    /** 다른 저장소(사내 미러 등)에서 받을 때는 {@code KSS_E2E_KEYCLOAK_IMAGE}에 이미지 전체 이름을 준다. */
    public static final String KEYCLOAK_IMAGE = env("KSS_E2E_KEYCLOAK_IMAGE",
        "quay.io/keycloak/keycloak:" + env("KSS_E2E_KEYCLOAK_VERSION", "26.8.2"));
    /** 다른 저장소에서 받을 때는 {@code KSS_E2E_POSTGRES_IMAGE}. */
    public static final String POSTGRES_IMAGE = env("KSS_E2E_POSTGRES_IMAGE", "postgres:16-alpine");

    private static E2eEnvironment instance;

    private final String keycloakUrl;
    private final String keycloakSource;
    private final String adminUsername;
    private final String adminPassword;
    private final String dbUrl;
    private final String dbUsername;
    private final String dbPassword;
    private final String dbSource;
    private final Path tlsDir;

    private E2eEnvironment(String keycloakUrl, String keycloakSource, String adminUsername, String adminPassword,
                           String dbUrl, String dbUsername, String dbPassword, String dbSource, Path tlsDir) {
        this.keycloakUrl = keycloakUrl;
        this.keycloakSource = keycloakSource;
        this.adminUsername = adminUsername;
        this.adminPassword = adminPassword;
        this.dbUrl = dbUrl;
        this.dbUsername = dbUsername;
        this.dbPassword = dbPassword;
        this.dbSource = dbSource;
        this.tlsDir = tlsDir;
    }

    /** 처음 부르면 띄우고, 그다음부터는 같은 것을 돌려준다. */
    public static synchronized E2eEnvironment get() {
        if (instance == null) {
            instance = start();
        }
        return instance;
    }

    private static E2eEnvironment start() {
        Path tlsDir = Path.of(requiredProperty("kss.e2e.tls-dir"));
        Path realmFile = Path.of(requiredProperty("kss.e2e.realm-file"));
        if (!Files.isRegularFile(tlsDir.resolve("server.p12"))) {
            throw new IllegalStateException("테스트 인증서가 없습니다: " + tlsDir + " (e2eTest 작업이 e2eCerts를 먼저 돌린다)");
        }

        String keycloakUrl = System.getenv("KSS_E2E_KEYCLOAK_URL");
        String keycloakSource;
        if (keycloakUrl != null && !keycloakUrl.isBlank()) {
            keycloakSource = "external";
        } else {
            requireDocker("KSS_E2E_KEYCLOAK_URL");
            GenericContainer<?> keycloak = new GenericContainer<>(DockerImageName.parse(KEYCLOAK_IMAGE))
                .withExposedPorts(8080)
                .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
                .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
                .withCopyFileToContainer(MountableFile.forHostPath(realmFile), "/opt/keycloak/data/import/realm-kss-demo.json")
                .withCopyFileToContainer(MountableFile.forHostPath(tlsDir.resolve("ca.pem")), "/opt/keycloak/conf/truststores/kss-test-ca.pem")
                // back-channel 로그아웃 때 Keycloak이 호스트의 샘플 앱(api.kss.test)을 부른다
                .withExtraHost("api.kss.test", "host-gateway")
                .withCommand("start-dev", "--import-realm", "--truststore-paths=/opt/keycloak/conf/truststores/kss-test-ca.pem")
                .waitingFor(Wait.forHttp("/realms/" + REALM + "/.well-known/openid-configuration")
                    .forPort(8080)
                    .withStartupTimeout(Duration.ofMinutes(3)));
            keycloak.start();
            Runtime.getRuntime().addShutdownHook(new Thread(keycloak::stop));
            keycloakUrl = "http://sso.kss.test:" + keycloak.getMappedPort(8080);
            keycloakSource = "testcontainers " + KEYCLOAK_IMAGE;
        }

        String dbUrl = System.getenv("KSS_E2E_DB_URL");
        String dbUsername;
        String dbPassword;
        String dbSource;
        if (dbUrl != null && !dbUrl.isBlank()) {
            dbUsername = env("KSS_E2E_DB_USERNAME", "kss");
            dbPassword = env("KSS_E2E_DB_PASSWORD", "kss");
            dbSource = "external";
        } else {
            requireDocker("KSS_E2E_DB_URL");
            PostgreSQLContainer postgres = new PostgreSQLContainer(DockerImageName.parse(POSTGRES_IMAGE).asCompatibleSubstituteFor("postgres"))
                .withDatabaseName("kss")
                .withUsername("kss")
                .withPassword("kss");
            postgres.start();
            Runtime.getRuntime().addShutdownHook(new Thread(postgres::stop));
            dbUrl = postgres.getJdbcUrl();
            dbUsername = postgres.getUsername();
            dbPassword = postgres.getPassword();
            dbSource = "testcontainers " + POSTGRES_IMAGE;
        }

        return new E2eEnvironment(trimSlash(keycloakUrl), keycloakSource,
            env("KSS_E2E_KEYCLOAK_ADMIN", "admin"), env("KSS_E2E_KEYCLOAK_ADMIN_PASSWORD", "admin"),
            dbUrl, dbUsername, dbPassword, dbSource, tlsDir);
    }

    private static void requireDocker(String alternative) {
        if (!DockerClientFactory.instance().isDockerAvailable()) {
            throw new IllegalStateException("Docker가 없습니다. 밖에 띄운 것을 쓰려면 " + alternative
                + "를 주세요 (integration-tests/keycloak/start-local.sh, docs/v3/03-검증-환경.md)");
        }
    }

    private static String requiredProperty(String name) {
        return Objects.requireNonNull(System.getProperty(name), name + " 시스템 속성이 없습니다. ./gradlew :integration-tests:servlet-app:e2eTest로 돌리세요");
    }

    private static String env(String name, String defaultValue) {
        String value = System.getenv(name);
        return (value == null || value.isBlank()) ? defaultValue : value;
    }

    private static String trimSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    /** 예: {@code http://sso.kss.test:8180} */
    public String keycloakUrl() {
        return keycloakUrl;
    }

    /** 예: {@code http://sso.kss.test:8180/realms/kss-demo} */
    public String issuer() {
        return keycloakUrl + "/realms/" + REALM;
    }

    public String keycloakSource() {
        return keycloakSource;
    }

    public String adminUsername() {
        return adminUsername;
    }

    public String adminPassword() {
        return adminPassword;
    }

    public String dbUrl() {
        return dbUrl;
    }

    public String dbUsername() {
        return dbUsername;
    }

    public String dbPassword() {
        return dbPassword;
    }

    public String dbSource() {
        return dbSource;
    }

    public Path tlsDir() {
        return tlsDir;
    }

    public Path caCertificate() {
        return tlsDir.resolve("ca.pem");
    }
}
