package com.ids.keycloak.security.authentication;

import java.util.Collections;
import org.springframework.security.authentication.AbstractAuthenticationToken;

/**
 * Back-Channel Logout 요청에서 logout_token을 전달하기 위한 Authentication 객체입니다.
 *
 * <p>{@link ReactiveOidcBackChannelLogoutHandler}에 logout_token JWT 문자열을
 * 전달하기 위한 내부 전용 Authentication 래퍼입니다.</p>
 */
public class BackChannelLogoutAuthentication extends AbstractAuthenticationToken {

  private final String logoutTokenJwt;

  /**
   * @param logoutTokenJwt Keycloak이 전달한 logout_token JWT 문자열
   */
  public BackChannelLogoutAuthentication(String logoutTokenJwt) {
    super(Collections.emptyList());
    this.logoutTokenJwt = logoutTokenJwt;
    setAuthenticated(false);
  }

  @Override
  public Object getCredentials() {
    return logoutTokenJwt;
  }

  @Override
  public Object getPrincipal() {
    return "back-channel-logout";
  }
}
