package com.ids.keycloak.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * V3-15 문서 (#91): 사용 가이드와 v2 → v3 옮기기 문서가 코드의 설정 키와 어긋나지 않는지 본다.
 * 설정 키는 configuration processor가 만든 {@code META-INF/spring-configuration-metadata.json}에서 읽는다.
 * 문서 폴더는 Gradle이 {@code kss.docs.dir}로 준다 (IDE에서는 작업 폴더에서 위로 찾는다).
 */
class KeycloakDocsTest {

    static final String PREFIX = "keycloak.security.";
    static final Pattern NAME = Pattern.compile("\"name\"\\s*:\\s*\"(keycloak\\.security\\.[^\"]+)\"");

    /** 스타터가 받는 설정 키 ({@code keycloak.security.} 뒤). */
    static List<String> keys() throws IOException {
        TreeSet<String> keys = new TreeSet<>();
        for (URL url : Collections.list(KeycloakDocsTest.class.getClassLoader().getResources("META-INF/spring-configuration-metadata.json"))) {
            try (InputStream in = url.openStream()) {
                Matcher m = NAME.matcher(new String(in.readAllBytes(), StandardCharsets.UTF_8));
                while (m.find()) {
                    keys.add(m.group(1).substring(PREFIX.length()));
                }
            }
        }
        assertThat(keys).as("설정 메타데이터").contains("frontend.base-url", "crypto.keys", "auto-filter-chain");
        return new ArrayList<>(keys);
    }

    static String doc(String name) throws IOException {
        String dir = System.getProperty("kss.docs.dir");
        Path docs = dir != null ? Path.of(dir) : findDocs();
        return Files.readString(docs.resolve(name), StandardCharsets.UTF_8);
    }

    private static Path findDocs() {
        for (Path p = Path.of("").toAbsolutePath(); p != null; p = p.getParent()) {
            if (Files.isRegularFile(p.resolve("docs/GUIDE.md"))) {
                return p.resolve("docs");
            }
        }
        throw new IllegalStateException("docs 폴더를 찾지 못했습니다. -Dkss.docs.dir로 주세요");
    }

    /** 문서에 키가 `키` 모양으로 있는가({@code `키: 값`}도). {@code crypto.keys}는 {@code crypto.keys.{id}}로 적는다. logging은 4-8 표에 짧은 이름으로 적는다. */
    static List<String> missing(String text, List<String> keys, boolean loggingByShortName) {
        List<String> missing = new ArrayList<>();
        for (String key : keys) {
            String written = key.startsWith("logging.") && loggingByShortName ? key.substring("logging.".length()) : key;
            if (!text.contains("`" + written + "`") && !text.contains("`" + written + ".") && !text.contains("`" + written + ":")) {
                missing.add(key);
            }
        }
        return missing;
    }

    @ParameterizedTest(name = "DOC-04 {0}의 설정 표·로그 표에 스타터 설정 키가 모두 있다")
    @ValueSource(strings = {"GUIDE.ko.md", "GUIDE.md"})
    void guideHasEveryKey(String file) throws IOException {
        assertThat(missing(doc(file), keys(), true)).as(file + "에 없는 설정 키").isEmpty();
    }

    @ParameterizedTest(name = "DOC-02 {0}에 바뀐 설정 키·빠진 기능과 대안·DB 스키마·Keycloak client 설정이 있고, logging 말고 3.x 설정 키가 모두 나온다")
    @ValueSource(strings = {"MIGRATION-v3.ko.md", "MIGRATION-v3.md"})
    void migrationHasEveryKeyAndSection(String file) throws IOException {
        String text = doc(file);
        List<String> nonLogging = keys().stream().filter(k -> !k.startsWith("logging.")).toList();
        assertThat(missing(text, nonLogging, false)).as(file + "에 없는 설정 키").isEmpty();
        assertThat(text)
            .as("v2 키와 대안").contains("`session.store-type: MEMORY \\| REDIS`", "`basic-auth.*`", "`bearer-token.*`", "`rate-limit.*`",
                "`role-mapping.*`", "`error.*`", "`logging.*`")
            .as("DB 스키마").contains("CREATE TABLE auth_session", "kss/schema-postgresql.sql")
            .as("Keycloak client").contains("Valid redirect URIs", "Valid post logout redirect URIs", "Backchannel logout URL",
                "Backchannel logout session required", "PKCE Method", "Client Session Idle");
    }
}
