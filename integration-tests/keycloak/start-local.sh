#!/usr/bin/env bash
# Docker 없이 E2E를 돌릴 때 Keycloak을 배포판으로 띄운다 (docs/v3/03-검증-환경.md 3절, E2E-02).
#
#   integration-tests/keycloak/start-local.sh            # http://sso.kss.test:8180 에 뜬다 (Ctrl+C로 끔)
#
# 그다음 다른 터미널에서:
#   KSS_E2E_KEYCLOAK_URL=http://sso.kss.test:8180 \
#   KSS_E2E_DB_URL=jdbc:postgresql://localhost:5432/kss KSS_E2E_DB_USERNAME=kss KSS_E2E_DB_PASSWORD=kss \
#   ./gradlew :integration-tests:servlet-app:e2eTest
#
# 환경 변수: KC_VERSION(기본 26.8.2), KC_HOME(이미 풀어 둔 배포판), KC_PORT(기본 8180)
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
KC_VERSION=${KC_VERSION:-26.8.2}
KC_PORT=${KC_PORT:-8180}
WORK=${KSS_E2E_WORK:-$HERE/../servlet-app/build/e2e}
KC_HOME=${KC_HOME:-$WORK/keycloak-$KC_VERSION}
mkdir -p "$WORK"

if [ ! -x "$KC_HOME/bin/kc.sh" ]; then
  echo "Keycloak $KC_VERSION 배포판을 받습니다: $KC_HOME"
  curl -fsSL "https://github.com/keycloak/keycloak/releases/download/$KC_VERSION/keycloak-$KC_VERSION.tar.gz" | tar -xz -C "$WORK"
fi

# 테스트 CA (back-channel 로그아웃 때 Keycloak이 샘플 앱 HTTPS를 믿도록)
"$HERE/gen-test-certs.sh" "$WORK/tls"

# *.kss.test 이름을 이 Keycloak JVM 안에서만 127.0.0.1로 푼다 (/etc/hosts를 고치지 않는다)
HOSTS="$WORK/hosts"
printf '127.0.0.1 localhost %s app.kss.test api.kss.test sso.kss.test\n::1 localhost\n' "$(hostname)" > "$HOSTS"

mkdir -p "$KC_HOME/data/import"
cp "$HERE/realm-kss-demo.json" "$KC_HOME/data/import/"

export KC_BOOTSTRAP_ADMIN_USERNAME=${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}
export KC_BOOTSTRAP_ADMIN_PASSWORD=${KC_BOOTSTRAP_ADMIN_PASSWORD:-admin}
export JAVA_OPTS_APPEND="${JAVA_OPTS_APPEND:-} -Djdk.net.hosts.file=$HOSTS"

exec "$KC_HOME/bin/kc.sh" start-dev \
  --http-port="$KC_PORT" \
  --import-realm \
  --truststore-paths="$WORK/tls/ca.pem"
