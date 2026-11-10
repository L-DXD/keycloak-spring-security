-- keycloak-spring-security v3 세션 행 (PostgreSQL). 앱의 마이그레이션(Flyway 등)에 그대로 넣는다.
-- 테이블 이름을 바꿨으면(keycloak.security.session.table-name) 아래 이름도 같이 바꾼다.
-- 앱이 열을 더 붙여도 된다(NULL 허용 또는 기본값). 라이브러리는 아래 열만 읽고 쓴다.
CREATE TABLE auth_session (
  id                  UUID         PRIMARY KEY,
  sid_hash            CHAR(64)     NOT NULL UNIQUE,
  keycloak_user_id    VARCHAR(64)  NOT NULL,
  kc_sid              VARCHAR(64)  NOT NULL,
  refresh_token_enc   BYTEA        NOT NULL,
  enc_key_id          VARCHAR(32)  NOT NULL,
  refresh_expires_at  TIMESTAMPTZ  NOT NULL,
  created_at          TIMESTAMPTZ  NOT NULL,
  absolute_expires_at TIMESTAMPTZ  NOT NULL,
  refreshed_at        TIMESTAMPTZ
);
CREATE INDEX ix_auth_session_kc_sid ON auth_session (kc_sid);
CREATE INDEX ix_auth_session_user   ON auth_session (keycloak_user_id);
CREATE INDEX ix_auth_session_abs    ON auth_session (absolute_expires_at);
