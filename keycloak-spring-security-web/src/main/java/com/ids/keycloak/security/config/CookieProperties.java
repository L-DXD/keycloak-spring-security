package com.ids.keycloak.security.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "keycloak.security.cookie")
public class CookieProperties {

    private boolean httpOnly = true;
    private boolean secure = false;
    private String domain;
    private String path = "/";
    private String sameSite; // Lax, Strict, None
}
