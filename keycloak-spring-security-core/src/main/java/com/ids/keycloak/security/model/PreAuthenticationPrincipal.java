package com.ids.keycloak.security.model;

import java.io.Serializable;
import java.security.Principal;

/**
 * JWT 토큰의 'sub' 클레임을 보관하는 {@link Principal} 구현체입니다.
 * 완전한 인증 전에 사용되는 임시, 미인증 Principal 입니다.
 *
 * @param subject JWT의 'sub' 클레임 값
 */
public record PreAuthenticationPrincipal(String subject) implements Principal, Serializable {

    @Override
    public String getName() {
        return this.subject;
    }
}
