-- keycloak-spring-security v3 세션 행 (H2 2.x). 개발·테스트용.
-- 테이블 이름을 바꿨으면(keycloak.security.session.table-name) 아래 이름도 같이 바꾼다.
CREATE TABLE auth_session (
  id                  UUID                     PRIMARY KEY,
  sid_hash            CHAR(64)                 NOT NULL UNIQUE,
  keycloak_user_id    VARCHAR(64)              NOT NULL,
  kc_sid              VARCHAR(64)              NOT NULL,
  refresh_token_enc   VARBINARY                NOT NULL,
  enc_key_id          VARCHAR(32)              NOT NULL,
  refresh_expires_at  TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at          TIMESTAMP WITH TIME ZONE NOT NULL,
  absolute_expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  refreshed_at        TIMESTAMP WITH TIME ZONE
);
CREATE INDEX ix_auth_session_kc_sid ON auth_session (kc_sid);
CREATE INDEX ix_auth_session_user   ON auth_session (keycloak_user_id);
CREATE INDEX ix_auth_session_abs    ON auth_session (absolute_expires_at);
