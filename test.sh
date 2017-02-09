#!/bin/sh
PING=${PING:-./mongoc-ping}
ROOT=$(dirname $PING)

run_test() {
   uri=$1
   result="FAILURE";
   if $PING "$i" &>/dev/null; then
      result="SUCCESS";
   fi
   printf "%10s: %s\n" "$result" "$uri"
}

PASS="
mongodb://im6uqskhja5ccrkykbhvevb2efqu4vkmjrafgvcsivheovcibjbucplsn5xxics.oii6tembrg4wteljrbjhecpjsgaytqljsfuyquu2bjy6usub2gezdolrqfyyc4m.ikifjquqsdhuzaus2vhuyqurklku6tocq.vcap.me:8888/?ssl=true&sslCertificateAuthorityFile=$ROOT/tests/x509gen/ca.pem
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

