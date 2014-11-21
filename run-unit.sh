./waf

if [ ! $? -eq 0 ]; then
      echo "./waf failed"
      exit 0
    fi

rm build/conf-test/test-ndns.db

#./build/unit-tests
#./build/unit-tests IterativeQueryController
#./build/unit-tests -t NameServer/UpdateValidatorFetch* -l test_suite

random=$RANDOM
#echo $random

#./build/bin/ndns-update /ndn/edu/thu /cs/shock -t TXT-${random} -o newContent1 -o newContent2 -o $random \
 
#-c /ndn/edu/thu/KEY/cs/shock/ksk-1416707830389/ID-CERT/%FD%00%00%01I%DA%5D%F9%60

#./build/bin/ndns-dig /ndn/edu/thu/cs/shock -t TXT-${random}

#./build/bin/ndns-dig /ndn/edu/thu/cs/shock -t TXT

#./build/bin/ndns-shot /ndn/NDNS/edu/NS

./build/bin/ndns-shot -d certs/ /ndn/KEY/edu/ucla/ksk-1397547577830/ID-CERT/%00%00%01H%FB%AA%D0w
#sudo ./waf install
