#!/usr/bin/env bash
# 로컬 확인용 Keycloak + PostgreSQL + 화면(nginx)을 Docker로 띄운다 (테스트 전용. integration-tests/compose.yaml)
#
#   integration-tests/local-stack.sh up       # 테스트 인증서를 만들고 띄운 뒤 다 뜰 때까지 기다린다
#   integration-tests/local-stack.sh down     # 끄고 지운다. 다음 up은 realm·DB가 처음 상태로 뜬다
#   integration-tests/local-stack.sh status   # 상태
#   integration-tests/local-stack.sh logs [keycloak|postgres|front]
#
# 화면(nginx)은 127.0.0.1:443을 쓴다. Docker Desktop은 'Allow privileged port mapping'(기본 켬)이 켜져 있어야 하고,
# rootless Docker·Podman은 sysctl net.ipv4.ip_unprivileged_port_start=443 이하가 필요하다. 이미 443을 쓰는 프로그램이 있으면 끈다.
# DB 포트를 바꾸려면 KSS_DB_PORT=5433 처럼 준다(아래 bootRun 명령도 그 포트로 안내한다).
#
# 띄운 뒤 샘플 앱은 이 PC에서 띄운다 (docs/v3/03-검증-환경.md 5절):
#   ./gradlew :integration-tests:servlet-app:bootRun                                       # demo  https://api.kss.test:8443
#   ./gradlew :integration-tests:servlet-app:bootRun --args=--spring.profiles.active=demo2  # demo2 https://api.kss.test:8444
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
TLS="$HERE/servlet-app/build/e2e/tls"
compose() { docker compose -f "$HERE/compose.yaml" "$@"; }

case "${1:-up}" in
  up)
    "$HERE/keycloak/gen-test-certs.sh" "$TLS"
    if [ ! -f "$TLS/app.key" ]; then
      echo "화면 인증서가 없습니다: $TLS/app.key (openssl이 필요합니다)" >&2
      exit 1
    fi
    # CA가 바뀌었으면(예: ./gradlew clean 뒤) 떠 있는 Keycloak·화면은 옛 CA 파일을 그대로 들고 있으므로 다시 만든다
    if [ -n "$(compose ps -q keycloak 2>/dev/null)" ]; then
      ca_in_stack=$(compose exec -T keycloak cat /opt/keycloak/conf/truststores/kss-test-ca.pem 2>/dev/null | cksum || true)
      if [ "$ca_in_stack" != "$(cksum < "$TLS/ca.pem")" ]; then
        echo "테스트 CA가 바뀌어 keycloak·front 컨테이너를 다시 만듭니다 (Keycloak realm은 처음 상태로 돌아갑니다)" >&2
        compose up -d --wait --force-recreate keycloak front
      fi
    fi
    compose up -d --wait
    db_url=""
    if [ -n "${KSS_DB_PORT:-}" ] && [ "$KSS_DB_PORT" != 5432 ]; then
      db_url="KSS_DB_URL=jdbc:postgresql://localhost:$KSS_DB_PORT/kss "
    fi
    cat <<MSG

떴습니다 (테스트 전용, 이 PC에서만 열림).
  Keycloak  http://sso.kss.test:8180  (관리자 admin / admin, 사용자 alice / alice-test-password, bob / bob-test-password)
  DB        localhost:${KSS_DB_PORT:-5432}  (kss / kss / kss)
  화면      https://app.kss.test

다음: 샘플 앱을 띄웁니다 (각각 다른 창에서)
  ${db_url}./gradlew :integration-tests:servlet-app:bootRun
  ${db_url}./gradlew :integration-tests:servlet-app:bootRun --args=--spring.profiles.active=demo2

브라우저가 *.kss.test를 이 PC로 찾게 합니다. 둘 중 하나:
  - /etc/hosts에 한 줄:  127.0.0.1 app.kss.test api.kss.test sso.kss.test
  - 또는 따로 띄운 크롬:  --host-resolver-rules="MAP *.kss.test 127.0.0.1" --user-data-dir=<빈 폴더>
테스트 CA($TLS/ca.pem)는 브라우저가 모르므로 처음 들어갈 때 인증서 경고가 뜹니다(테스트 전용이라 넘겨도 됩니다).
MSG
    ;;
  down)
    compose down --volumes --remove-orphans
    ;;
  status)
    compose ps
    ;;
  logs)
    shift
    compose logs --follow ${1+"$@"}   # macOS 기본 bash 3.2에서 set -u와 빈 "$@"가 부딪히지 않게
    ;;
  *)
    echo "사용: $0 up | down | status | logs [서비스]" >&2
    exit 2
    ;;
esac
