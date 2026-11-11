#!/usr/bin/env bash
# E2E·로컬 실행 전용 테스트 CA와 인증서를 만든다. 이미 있으면 그대로 둔다.
#   - ca.pem / server.p12: 샘플 앱 HTTPS(api.kss.test). Keycloak은 back-channel 호출 때 이 CA를 믿는다
#   - app.crt / app.key: 로컬 화면(nginx, integration-tests/compose.yaml)의 HTTPS(app.kss.test 등). openssl이 있을 때만 만든다
#   키는 저장소에 넣지 않는다(빌드 폴더에만 생긴다). 비밀번호는 테스트 값이다.
# 사용: gen-test-certs.sh <출력 폴더>
set -euo pipefail

OUT=${1:?출력 폴더를 주세요}
PASS=changeit
KEYTOOL=${JAVA_HOME:+$JAVA_HOME/bin/}keytool
mkdir -p "$OUT"

LOG="$OUT/keytool.log"
kt() { "$KEYTOOL" -J-Duser.language=en "$@" >>"$LOG" 2>&1 || { cat "$LOG" >&2; return 1; }; }

if [ ! -f "$OUT/server.p12" ] || [ ! -f "$OUT/ca.pem" ] || [ ! -f "$OUT/ca.p12" ]; then
  # CA를 새로 만들면 그 CA로 서명한 것도 모두 다시 만든다
  if [ -f "$OUT/ca.pem" ] || [ -f "$OUT/server.p12" ]; then
    echo "테스트 CA를 새로 만듭니다. local-stack을 띄워 두었다면 local-stack.sh up이 Keycloak·화면을 새 CA로 다시 만듭니다" >&2
  fi
  rm -f "$OUT"/ca.p12 "$OUT"/ca.pem "$OUT"/server.p12 "$OUT"/server.csr "$OUT"/server.pem "$OUT"/app.crt "$OUT"/app.key
  : > "$LOG"

  # 테스트 CA
  kt -genkeypair -alias ca -keyalg EC -groupname secp256r1 -dname "CN=kss e2e test CA" \
     -ext bc:c -validity 3650 -keystore "$OUT/ca.p12" -storetype PKCS12 -storepass "$PASS" -keypass "$PASS"
  kt -exportcert -rfc -alias ca -keystore "$OUT/ca.p12" -storepass "$PASS" -file "$OUT/ca.pem"

  # 샘플 앱 서버 인증서 (api.kss.test, localhost)
  kt -genkeypair -alias server -keyalg EC -groupname secp256r1 -dname "CN=api.kss.test" \
     -validity 3650 -keystore "$OUT/server.p12" -storetype PKCS12 -storepass "$PASS" -keypass "$PASS"
  kt -certreq -alias server -keystore "$OUT/server.p12" -storepass "$PASS" -file "$OUT/server.csr"
  kt -gencert -alias ca -keystore "$OUT/ca.p12" -storepass "$PASS" -infile "$OUT/server.csr" -outfile "$OUT/server.pem" -rfc \
     -ext "SAN=dns:api.kss.test,dns:localhost" -ext "EKU=serverAuth" -ext "KU=digitalSignature" -validity 3650
  kt -importcert -alias ca -keystore "$OUT/server.p12" -storepass "$PASS" -file "$OUT/ca.pem" -noprompt
  kt -importcert -alias server -keystore "$OUT/server.p12" -storepass "$PASS" -file "$OUT/server.pem"
  rm -f "$OUT/server.csr"
fi

# 로컬 화면 인증서 (app.kss.test, 그리고 브라우저 확인에서 다른 화면으로 쓰는 evil.kss.test·evil.test). nginx가 읽는 PEM.
# 키와 서명 요청은 openssl로 만들고(PKCS12를 openssl로 풀지 않아 macOS의 LibreSSL에서도 된다), 서명은 위 테스트 CA로 keytool이 한다
if [ ! -f "$OUT/app.crt" ] || [ ! -f "$OUT/app.key" ]; then
  if command -v openssl >/dev/null 2>&1; then
    rm -f "$OUT/app.csr" "$OUT/app.crt" "$OUT/app.key"
    # MSYS_NO_PATHCONV: Windows Git Bash가 -subj의 "/CN=..."을 파일 경로로 바꾸지 않게 한다 (Linux·macOS에선 아무 일도 안 한다)
    if { openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/app.key" \
          && MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' openssl req -new -key "$OUT/app.key" -subj "/CN=app.kss.test" -out "$OUT/app.csr"; } >>"$LOG" 2>&1; then
      kt -gencert -alias ca -keystore "$OUT/ca.p12" -storepass "$PASS" -infile "$OUT/app.csr" -outfile "$OUT/app.crt" -rfc \
         -ext "SAN=dns:app.kss.test,dns:evil.kss.test,dns:evil.test" -ext "EKU=serverAuth" -ext "KU=digitalSignature" -validity 3650
      rm -f "$OUT/app.csr"
    else
      # 화면 인증서는 local-stack에만 쓴다. 여기서 멈추면 E2E·bootRun까지 막히므로 경고만 하고 넘어간다
      echo "openssl로 로컬 화면 인증서(app.crt, app.key)를 만들지 못했습니다. E2E에는 필요 없습니다. 자세한 내용: $LOG" >&2
      rm -f "$OUT/app.csr" "$OUT/app.key"
    fi
  else
    echo "openssl이 없어 로컬 화면 인증서(app.crt, app.key)는 만들지 않았습니다. E2E에는 필요 없습니다" >&2
  fi
fi
