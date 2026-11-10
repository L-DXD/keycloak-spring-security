package com.ids.keycloak.security.sample;

import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.ids.keycloak.security.authentication.KeycloakPrincipal;

/**
 * 화면(app.kss.test)이 부르는 API 흉내.
 */
@RestController
class SampleController {

    /** 로그인 필요. 누구로 로그인했는지 돌려준다. 라이브러리가 액세스 토큰에서 만든 사용자를 그대로 받는다. */
    @GetMapping(path = "/api/me", produces = MediaType.APPLICATION_JSON_VALUE)
    Map<String, Object> me(@AuthenticationPrincipal KeycloakPrincipal user) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("sub", user.subject());
        body.put("username", user.username());
        return body;
    }

    /** 로그인 없이 허용. */
    @GetMapping(path = "/api/public/ping", produces = MediaType.APPLICATION_JSON_VALUE)
    Map<String, Object> ping() {
        return Map.of("pong", true);
    }

    /** 로그인 + CSRF 필요. 받은 것을 그대로 돌려준다. */
    @PostMapping(path = "/api/items", produces = MediaType.APPLICATION_JSON_VALUE)
    Map<String, Object> createItem(@RequestBody Map<String, Object> item, Principal principal) {
        Map<String, Object> body = new LinkedHashMap<>(item);
        body.put("createdBy", principal.getName());
        return body;
    }

    /** 로그아웃 뒤 화면 주소 흉내. 실제로는 화면(app.kss.test)에 있다. */
    @GetMapping(path = "/logged-out", produces = MediaType.TEXT_PLAIN_VALUE)
    String loggedOut() {
        return "logged out";
    }
}
