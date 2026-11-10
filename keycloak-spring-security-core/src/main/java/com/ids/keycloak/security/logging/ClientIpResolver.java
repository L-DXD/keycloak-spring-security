package com.ids.keycloak.security.logging;

import java.util.regex.Pattern;

/**
 * 로그에 남길 클라이언트 IP를 고른다. {@code X-Forwarded-For}는 클라이언트가 마음대로 쓸 수 있으므로, 앞에 있는 믿을 수 있는
 * 프록시 수({@code trusted-proxy-count})만큼만 오른쪽에서 센다.
 * <pre>
 * X-Forwarded-For: fake, real, p1     (프록시마다 자기가 본 주소를 오른쪽에 붙인다. 예: nginx $proxy_add_x_forwarded_for)
 * trusted-proxy-count=0 → 헤더를 보지 않고 TCP 주소 (기본)
 * trusted-proxy-count=2 → parts[3 - 2] = "real" (바깥 프록시가 본 클라이언트 주소. 왼쪽 "fake"는 클라이언트가 쓴 값)
 * </pre>
 * 프록시 수가 항목 수보다 많으면(설정이 틀렸거나 헤더가 잘렸다)
 * 위조를 막으려고 TCP 주소를 쓴다. {@code -1}은 v2 호환으로 첫 값을 그대로 믿는다(권하지 않음. 시작할 때 경고).
 * IP에 쓰지 않는 글자가 있거나 너무 길면 {@code unknown}으로 남긴다(로그 끼워 넣기 방지).
 */
public class ClientIpResolver {

    /** IPv4, IPv6(대괄호·zone 포함), 포트. 그 밖의 글자는 받지 않는다. */
    private static final Pattern IP = Pattern.compile("[0-9A-Za-z.:%\\[\\]_-]{1,64}");

    static final String UNKNOWN = "unknown";

    private ClientIpResolver() {
    }

    /**
     * @param xffHeader         {@code X-Forwarded-For} 값 (없으면 {@code null})
     * @param remoteAddr        TCP 주소 ({@code request.getRemoteAddr()})
     * @param trustedProxyCount 앞에 있는 믿을 수 있는 프록시 수. 0이면 헤더를 보지 않는다. -1이면 첫 값(권하지 않음)
     * @return 클라이언트 IP. 고르지 못하면 {@code unknown}
     */
    public static String resolve(String xffHeader, String remoteAddr, int trustedProxyCount) {
        if (trustedProxyCount == 0 || xffHeader == null || xffHeader.isBlank()) {
            return clean(remoteAddr);
        }
        String[] parts = xffHeader.split(",");
        if (trustedProxyCount < 0) {
            return clean(parts[0]);
        }
        int index = parts.length - trustedProxyCount;
        return index < 0 ? clean(remoteAddr) : clean(parts[index]);
    }

    private static String clean(String ip) {
        if (ip == null) {
            return UNKNOWN;
        }
        String trimmed = ip.trim();
        return IP.matcher(trimmed).matches() ? trimmed : UNKNOWN;
    }
}
