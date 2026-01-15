package com.ids.keycloak.security.test.servlet;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import com.ids.keycloak.security.test.servlet.support.WithMockOidcLogin;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class OidcLoginIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    /**
     * 인증되지 않은 사용자가 보호된 API에 접근할 때,
     * Spring Security의 `oauth2Login`에 의해 OIDC 제공자의 인증 페이지로
     * 리디렉션되는지 확인합니다.
     *
     * @throws Exception MockMvc 수행 중 예외 발생 시
     */
    @Test
    void whenUnauthenticated_thenRedirectToLogin() throws Exception {
        mockMvc.perform(get("/api/me"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("/oauth2/authorization/keycloak")));
    }

    /**
     * `@WithMockOidcLogin`을 사용하여 가짜 OIDC 사용자로 인증된 상태를 시뮬레이션합니다.
     * 이 상태에서 보호된 API에 접근했을 때 200 OK 응답을 받는지 확인합니다.
     *
     * @throws Exception MockMvc 수행 중 예외 발생 시
     */
    @Test
    @WithMockOidcLogin
    void whenAuthenticatedWithOidcLogin_thenCanAccessApi() throws Exception {
        mockMvc.perform(get("/api/me"))
                .andExpect(status().isOk())
                .andExpect(result -> org.assertj.core.api.Assertions.assertThat(result.getResponse().getContentAsString()).contains("Hello, user"));
    }
}
