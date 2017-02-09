#!/bin/sh
PING=${PING:-./mongoc-ping}
ROOT=$(dirname $PING)

run_test() {
   uri=$1
   out=$($PING "$i" 2>&1)
   result="FAILURE";
   if [ "$out" = "{ \"ok\" : 1.0 }" ]; then
      result="SUCCESS";
   fi
   printf "%10s: %s\n" "$result" "$uri"
}

PASS="
mongodb://some.server.pass.vcap.me:8888/?ssl=true&sslCertificateAuthorityFile=$ROOT/tests/x509gen/ca.pem
";

FAIL="
mongodb://some.server.fail.vcap.me:8888/?ssl=true&sslCertificateAuthorityFile=$ROOT/tests/x509gen/ca.pem
";

echo "----------------------- SHOULD SUCCEED -----------------------"
for i in $PASS; do
   run_test "$i"
done

echo "----------------------- SHOULD FAIL -----------------------"
for i in $FAIL; do
   run_test "$i"
done

