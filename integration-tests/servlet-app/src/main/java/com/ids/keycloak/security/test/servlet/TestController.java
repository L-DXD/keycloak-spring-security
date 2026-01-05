package com.ids.keycloak.security.test.servlet;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/api/me")
    public ResponseEntity<String> getMyInfo(@AuthenticationPrincipal OAuth2User principal) {
        if (principal != null) {
            return ResponseEntity.ok("Hello, " + principal.getName());
        }
        return ResponseEntity.status(401).body("Unauthorized");
    }
}