#!/bin/sh
PING=${PING:-./mongoc-ping}
ROOT=$(dirname $PING)

run_test() {
   uri=$1
   result="FAILURE";
   
   if $PING "$i" >/dev/null; then
      result="SUCCESS";
   fi
   printf "%10s: %s\n" "$result" "$uri"
}

run_config_test() {
   config_file=$1
   # Convert into base32 and split into 63 character labels.
   encoded=$(base32 ${config_file} | tr -d '\n' | sed -E 's/(.{64})/\1./g')
   encoded_host="${encoded}.vcap.me"
   run_test "mongodb://${encoded_host}:8888/?ssl=true&sslCertificateAuthorityFile=$ROOT/tests/x509gen/ca.pem"
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

for good_config in ./config/good*; do
   run_config_test "$good_config"
done

echo "----------------------- SHOULD FAIL -----------------------"
for i in $FAIL; do
   run_test "$i"
done

for bad_config in ./config/bad*; do
   run_config_test "$bad_config"
done
