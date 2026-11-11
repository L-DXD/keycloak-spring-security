package com.ids.keycloak.security;

/**
 * 라이브러리 판 정보. jar 매니페스트의 {@code Implementation-Version}을 읽는다.
 * <p>
 * jar가 아닌 곳(IDE, 테스트 classes 폴더)에서 돌면 {@link #UNKNOWN}을 돌려준다.
 */
public class KeycloakSecurityVersion {

    /** 판을 알 수 없을 때의 값. */
    public static final String UNKNOWN = "unknown";

    protected KeycloakSecurityVersion() {
    }

    /**
     * 지금 쓰고 있는 라이브러리 판.
     *
     * @return 예: {@code 3.0.0}. 모르면 {@link #UNKNOWN}
     */
    public static String current() {
        String version = KeycloakSecurityVersion.class.getPackage().getImplementationVersion();
        return (version == null || version.isBlank()) ? UNKNOWN : version;
    }
}
