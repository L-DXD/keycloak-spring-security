package com.ids.keycloak.security.sample.e2e;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import com.ids.keycloak.security.sample.SampleApplication;

/**
 * 샘플 앱을 테스트 JVM 안에서 띄운다. 앱 하나(client)당 한 번만 띄우고 JVM이 끝날 때 내린다.
 * <ul>
 *   <li>{@link #demo()}: client {@code demo}, {@code https://api.kss.test:8443}</li>
 *   <li>{@link #demo2()}: client {@code demo2}, {@code https://api.kss.test:8444} (SSO·back-channel 시나리오)</li>
 * </ul>
 */
public final class SampleApps {

    private static final Map<String, Running> RUNNING = new HashMap<>();

    private SampleApps() {
    }

    public static Running demo() {
        return start("demo", 8443, null);
    }

    public static Running demo2() {
        return start("demo2", 8444, "demo2");
    }

    private static synchronized Running start(String clientId, int port, String profile) {
        return RUNNING.computeIfAbsent(clientId, id -> {
            E2eEnvironment env = E2eEnvironment.get();
            Map<String, Object> properties = new LinkedHashMap<>();
            properties.put("kss.keycloak.url", env.keycloakUrl());
            properties.put("kss.db.url", env.dbUrl());
            properties.put("kss.db.username", env.dbUsername());
            properties.put("kss.db.password", env.dbPassword());
            properties.put("kss.tls-dir", env.tlsDir().toString());
            properties.put("spring.main.banner-mode", "off");

            E2eClock clock = new E2eClock();
            SpringApplicationBuilder builder = new SpringApplicationBuilder(SampleApplication.class).properties(properties)
                .initializers(context -> context.getBeanFactory().registerSingleton("keycloakSecurityClock", clock));
            if (profile != null) {
                builder.profiles(profile);
            }
            ConfigurableApplicationContext context = builder.run();
            Runtime.getRuntime().addShutdownHook(new Thread(context::close));
            return new Running(clientId, "https://api.kss.test:" + port, context, clock);
        });
    }

    /** 떠 있는 샘플 앱 하나. */
    public record Running(String clientId, String baseUrl, ConfigurableApplicationContext context, E2eClock clock) {

        public String url(String path) {
            return baseUrl + path;
        }
    }
}
