package com.ids.keycloak.security.sample.e2e;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ServerSocket;

import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

import com.ids.keycloak.security.web.refresh.DefaultKeycloakTokenClient;
import com.ids.keycloak.security.web.refresh.KeycloakTokenClient;
import com.ids.keycloak.security.web.refresh.KeycloakTokenResponse;

/**
 * Keycloak에 닿지 않는 상황(REFRESH-06, 로그아웃 실패)을 만든다. 공용 Keycloak을 실제로 멈추면 다른 테스트와 앱이 같이 흔들리므로,
 * 샘플 앱의 {@link KeycloakTokenClient} 빈을 감싸 {@link #begin()} 동안만 같은 설정의 기본 클라이언트를 닫힌 포트로 보낸다(갱신·로그아웃·폐기 모두).
 * 앱 안의 코드는 그대로 돌고, 연결 거부도 실제로 일어난다.
 */
public class KeycloakOutage implements BeanPostProcessor {

    private volatile boolean down;
    private volatile ConfigurableApplicationContext context;
    private volatile KeycloakTokenClient unreachable;

    void attach(ConfigurableApplicationContext context) {
        this.context = context;
    }

    /** 이제부터 갱신 요청이 Keycloak에 닿지 않는다. */
    public void begin() {
        down = true;
    }

    /** Keycloak에 다시 닿는다. */
    public void end() {
        down = false;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) {
        if (bean instanceof KeycloakTokenClient real) {
            return new KeycloakTokenClient() {
                @Override
                public KeycloakTokenResponse refresh(String refreshToken) {
                    return client(real).refresh(refreshToken);
                }

                @Override
                public void logout(String refreshToken) {
                    client(real).logout(refreshToken);
                }

                @Override
                public void revoke(String refreshToken) {
                    client(real).revoke(refreshToken);
                }
            };
        }
        return bean;
    }

    private KeycloakTokenClient client(KeycloakTokenClient real) {
        return down ? unreachable() : real;
    }

    private KeycloakTokenClient unreachable() {
        if (unreachable == null) {
            ClientRegistration registration = context.getBean(ClientRegistrationRepository.class).findByRegistrationId("keycloak");
            unreachable = new DefaultKeycloakTokenClient(ClientRegistration.withClientRegistration(registration)
                .tokenUri("http://127.0.0.1:" + closedPort() + "/token")
                .providerConfigurationMetadata(java.util.Map.of())
                .issuerUri("http://127.0.0.1:" + closedPort() + "/realms/down")
                .build());
        }
        return unreachable;
    }

    private static int closedPort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
