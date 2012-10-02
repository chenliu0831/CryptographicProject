#!/bin/bash

rmmod sys_xcrypt

make clean

rm test_BIGGER_*

rm test_SMALL_*

rm test_ZERO_SIZE_*

rm test_PAGE_SIZE_*

rm test_EXTRA_CREDIT_*

rm test_DES3_*

rm test_BAD_INPUT_*