package com.ids.keycloak.security.config;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.event.ApplicationStartedEvent;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;

/**
 * 라이브러리 시작 시 배너를 출력하는 자동 설정 클래스입니다.
 * 사용 중인 라이브러리의 버전과 웹 스택(Servlet/WebFlux) 정보를 콘솔에 표시합니다.
 */
@AutoConfiguration
public class KeycloakBannerAutoConfiguration {

    /**
     * 애플리케이션 시작 시점에 배너를 출력하는 리스너를 생성합니다.
     * 
     * @return ApplicationListener<ApplicationStartedEvent>
     */
    @Bean
    public ApplicationListener<ApplicationStartedEvent> keycloakBannerPrinter() {
        return event -> {
            ApplicationContext context = event.getApplicationContext();
            String webStack = "servlet"; // 현재 모듈이 servlet-starter이므로 servlet으로 고정
            
            // Manifest 파일로부터 버전 정보를 읽어옵니다.
            String version = KeycloakBannerAutoConfiguration.class.getPackage().getImplementationVersion();
            if (version == null) {
                // IDE에서 바로 실행하는 등 manifest 파일이 없을 경우를 위한 대체 버전 정보
                version = "1.0.0-SNAPSHOT";
            }
            
            // 콘솔에 컬러 배너 출력 (노란색)
            System.out.println("\u001B[33m"); 
            System.out.println("  Keycloak Spring Security Library v" + version);
            System.out.println("  Active Web Environment: " + webStack);
            System.out.println("\u001B[0m"); 
        };
    }
}
