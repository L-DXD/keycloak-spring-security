-- 샘플 앱 기준선. 세션 테이블(auth_session)은 V2 (라이브러리 kss/schema-postgresql.sql + 앱 열)
CREATE TABLE sample_item (
    id         BIGSERIAL    PRIMARY KEY,
    name       VARCHAR(200) NOT NULL,
    created_by VARCHAR(200) NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);
