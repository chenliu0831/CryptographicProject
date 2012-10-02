#!/bin/bash

make clean

make all

rmmod sys_xcrypt
insmod sys_xcrypt.ko

echo 1.
echo Testing File smaller than PAGE_SIZE

./xcipher -p lcy890831  -e  test_SMALL test_SMALL_enc

./xcipher -p lcy890831 -d test_SMALL_enc test_SMALL_dec

echo 2.
echo Testing Bigger file 

./xcipher -p lcy890831 -e test_BIGGER test_BIGGER_enc

./xcipher -p lcy890831 -d test_BIGGER_enc test_BIGGER_dec

echo 3.
echo Testing zero size file

./xcipher -p lcy890831 -e test_ZERO_SIZE test_ZERO_SIZE_enc

./xcipher -p lcy890831 -d test_ZERO_SIZE_enc test_ZERO_SIZE_dec


echo "4."
echo Testing PAGE_SIZE file

./xcipher -p stonybrookcs -e test_PAGE_SIZE test_PAGE_SIZE_enc

./xcipher -p stonybrookcs -d test_PAGE_SIZE_enc test_PAGE_SIZE_dec

echo 5.
echo Extra Credit test

./xcipher -p sbcs506 -c "cbc(blowfish)" -u 16050 -l 256 -e  test_EXTRA_CREDIT test_EXTRA_CREDIT_enc
./xcipher -p sbcs506 -c "cbc(blowfish)" -u 16050 -l 256 -d  test_EXTRA_CREDIT_enc test_EXTRA_CREDIT_dec

echo 6. 
echo Extra Credit test 2

./xcipher -p sbcs506 -c "cbc(des3_ede)" -u 13041 -l 128 -e test_DES3 test_DES3_enc

./xcipher -p sbcs506 -c "cbc(des3_ede)" -u 13041 -l 128 -d test_DES3_enc test_DES3_dec


