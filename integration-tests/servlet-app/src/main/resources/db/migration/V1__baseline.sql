-- 샘플 앱 기준선. 세션 테이블(auth_session)은 #80에서 스타터의 kss/schema-postgresql.sql을 그대로 옮겨 V2로 넣는다
CREATE TABLE sample_item (
    id         BIGSERIAL    PRIMARY KEY,
    name       VARCHAR(200) NOT NULL,
    created_by VARCHAR(200) NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);
