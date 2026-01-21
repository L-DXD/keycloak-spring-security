package com.ids.keycloak.security.test.servlet;

import com.ids.keycloak.security.model.KeycloakPrincipal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class TestController {

    @GetMapping("/api/me")
    public ResponseEntity<String> getMyInfo(@AuthenticationPrincipal KeycloakPrincipal principal) {
        if (principal != null) {
            log.debug("인증된 사용자: {}", principal.getName()); // 실질적인 sub 이네...? 흠.. 추가적인 정보가 담겨야할 것 같은데
            log.debug("사용자 속성: {}", principal.getAttributes());
            log.debug("사용자 권한: {}", principal.getAuthorities());
            return ResponseEntity.ok("Hello, " + principal.getName());
        }

        return ResponseEntity.status(401).body("Unauthorized");
    }
}