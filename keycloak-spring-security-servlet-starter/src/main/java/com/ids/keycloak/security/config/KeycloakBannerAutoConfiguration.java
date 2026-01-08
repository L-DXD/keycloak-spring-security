package com.ids.keycloak.security.config;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.event.ApplicationStartedEvent;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class KeycloakBannerAutoConfiguration {

    @Bean
    public ApplicationListener<ApplicationStartedEvent> keycloakBannerPrinter() {
        return event -> {
            ApplicationContext context = event.getApplicationContext();
            String webStack = "servlet";
            String version = KeycloakBannerAutoConfiguration.class.getPackage().getImplementationVersion();
            if (version == null) {
                // IDE에서 바로 실행하는 등 manifest 파일이 없을 경우를 위한 대체 버전 정보
                version = "1.0.0-SNAPSHOT";
            }
            
            System.out.println("\u001B[33m"); // 노란색으로 설정
            System.out.println("  Keycloak Spring Security Library v" + version);
            System.out.println("  Active Web Environment: " + webStack);
            System.out.println("\u001B[0m"); // 색상 초기화
        };
    }
}
