#!/bin/bash

make clean

make all

insmod sys_xcrypt.ko

./xcipher -p lcy890831  -c "cbc(aes)" -u 16020 -l 256 -e maintain maintain_enc

./xcipher -p lcy890831  -c "cbc(aes)" -u 16020 -l 256 -d maintain_enc maintain_dec