package com.ids.keycloak.security.sample;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * v3 샘플 앱 (가상 프로젝트). 실제 앱이 라이브러리를 쓰는 모습 그대로 둔다.
 * <p>
 * 화면은 없다. 화면이 부르는 API와 로그아웃 뒤 주소만 흉내 낸다.
 * 설정: {@code application.yml}, 두 번째 앱은 프로필 {@code demo2}.
 */
@SpringBootApplication
public class SampleApplication {

    public static void main(String[] args) {
        SpringApplication.run(SampleApplication.class, args);
    }
}
