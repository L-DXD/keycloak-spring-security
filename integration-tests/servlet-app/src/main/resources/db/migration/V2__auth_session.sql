-- 세션 테이블: 라이브러리 jar의 kss/schema-postgresql.sql을 그대로 옮겼다 (#81).
-- 라이브러리를 올릴 때 CHANGELOG에 스키마 변경이 있으면 새 V 파일로 따라간다.
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

-- 앱이 붙인 열 (STORE-07). 라이브러리는 이 열을 읽지도 쓰지도 않는다
ALTER TABLE auth_session ADD COLUMN display_name VARCHAR(200);
