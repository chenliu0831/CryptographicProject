#!/bin/bash


make clean

make all

rmmod sys_xcrypt
insmod sys_xcrypt.ko

#TEST shell script for Various bad input

echo 1.
echo Testing wrong key...
./xcipher -p lcy890831  -e  test_BAD_INPUT test_BAD_INPUT_enc

./xcipher -p lcy82331 -d test_BAD_INPUT_enc BAD_INPUT_dec

echo 2. 
echo Testing not a regular file

./xcipher -p lcy890831  -e  DIR_TEST DIR_TEST_enc


echo 3. 
echo Testing input and output point to same file

./xcipher -p lcy890831 -e test_BAD_INPUT test_BAD_INPUT

