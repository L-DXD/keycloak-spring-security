package com.ids.keycloak.security.token;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.time.Duration;

import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;

/**
 * 기본 JWKS 받기. Nimbus {@link DefaultResourceRetriever}로 HTTP GET 한다 (연결 2초, 읽기 3초, 512KB 제한).
 */
public class NimbusJwkSetFetcher implements JwkSetFetcher {

    private static final int SIZE_LIMIT = 512 * 1024;

    private final URL jwkSetUrl;
    private final ResourceRetriever retriever;

    public NimbusJwkSetFetcher(URI jwkSetUri) {
        this(jwkSetUri, Duration.ofSeconds(2), Duration.ofSeconds(3));
    }

    public NimbusJwkSetFetcher(URI jwkSetUri, Duration connectTimeout, Duration readTimeout) {
        try {
            this.jwkSetUrl = jwkSetUri.toURL();
        } catch (Exception e) {
            throw new IllegalArgumentException("JWKS 주소가 아니다: " + jwkSetUri, e);
        }
        this.retriever = new DefaultResourceRetriever((int) connectTimeout.toMillis(), (int) readTimeout.toMillis(), SIZE_LIMIT);
    }

    @Override
    public String fetch() throws IOException {
        Resource resource = retriever.retrieveResource(jwkSetUrl);
        return resource.getContent();
    }

    @Override
    public String toString() {
        return "NimbusJwkSetFetcher[" + jwkSetUrl + "]";
    }
}
