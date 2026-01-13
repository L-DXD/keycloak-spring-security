package com.ids.keycloak.security.test.servlet;

import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
@RestController
@Slf4j
public class ServletApp {
    public static void main(String[] args) {
        SpringApplication.run(ServletApp.class, args);
    }

    @GetMapping("/session-test")
    public Map<String, Object> sessionTest(HttpSession session) {
        Integer count = (Integer) session.getAttribute("count");
        if (count == null) {
            count = 0;
        }
        session.setAttribute("count", ++count);

        Map<String, Object> result = new HashMap<>();
        result.put("sessionId", session.getId());
        result.put("count", count);
        result.put("sessionClass", session.getClass().getName());
        
        log.info("Session ID: {}, Count: {}, Class: {}", session.getId(), count, session.getClass().getName());
        return result;
    }
}