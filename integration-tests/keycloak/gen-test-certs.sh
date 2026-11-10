#!/usr/bin/env bash
# E2E 전용 테스트 CA와 서버 인증서를 만든다. 이미 있으면 그대로 둔다.
#   샘플 앱 HTTPS(api.kss.test) 와 Keycloak의 back-channel 호출(신뢰할 CA)에 쓴다.
#   키는 저장소에 넣지 않는다. 비밀번호는 테스트 값이다.
# 사용: gen-test-certs.sh <출력 폴더>
set -euo pipefail

OUT=${1:?출력 폴더를 주세요}
PASS=changeit
KEYTOOL=${JAVA_HOME:+$JAVA_HOME/bin/}keytool

if [ -f "$OUT/server.p12" ] && [ -f "$OUT/ca.pem" ]; then
  exit 0
fi
mkdir -p "$OUT"
rm -f "$OUT"/ca.p12 "$OUT"/ca.pem "$OUT"/server.p12 "$OUT"/server.csr "$OUT"/server.pem

LOG="$OUT/keytool.log"
: > "$LOG"
kt() { "$KEYTOOL" -J-Duser.language=en "$@" >>"$LOG" 2>&1 || { cat "$LOG" >&2; return 1; }; }

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
