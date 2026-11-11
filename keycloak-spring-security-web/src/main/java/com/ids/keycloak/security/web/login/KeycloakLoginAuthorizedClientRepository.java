package com.ids.keycloak.security.web.login;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 로그인 콜백에서 받은 토큰을 그 요청 안에서만 들고 있다가 로그인 성공 처리기에 넘긴다.
 * 메모리·HttpSession에 토큰을 남기지 않는다 (Spring 기본 저장소는 서버 메모리에 토큰을 쌓는다).
 */
public class KeycloakLoginAuthorizedClientRepository implements OAuth2AuthorizedClientRepository {

    /** 요청 속성 이름. */
    public static final String ATTRIBUTE = KeycloakLoginAuthorizedClientRepository.class.getName() + ".CLIENT";

    @Override
    @SuppressWarnings("unchecked")
    public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, Authentication principal,
                                                                     HttpServletRequest request) {
        Object client = request.getAttribute(ATTRIBUTE);
        if (client instanceof OAuth2AuthorizedClient c && c.getClientRegistration().getRegistrationId().equals(clientRegistrationId)) {
            return (T) c;
        }
        return null;
    }

    @Override
    public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal, HttpServletRequest request,
                                     HttpServletResponse response) {
        request.setAttribute(ATTRIBUTE, authorizedClient);
    }

    @Override
    public void removeAuthorizedClient(String clientRegistrationId, Authentication principal, HttpServletRequest request,
                                       HttpServletResponse response) {
        request.removeAttribute(ATTRIBUTE);
    }

    /** 이 요청에서 받은 토큰. */
    public static OAuth2AuthorizedClient current(HttpServletRequest request) {
        return request.getAttribute(ATTRIBUTE) instanceof OAuth2AuthorizedClient c ? c : null;
    }
}
