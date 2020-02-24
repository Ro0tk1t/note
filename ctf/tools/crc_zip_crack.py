#!/usr/bin/env python
# coding=utf-8

import binascii
import string

dic = string.printable
#输入密码文件的CRC码
crcl = [0xF3B61B38,0xF3B61B38]
key = ''
for crc in crcl:
    for i in dic:
        if crc==(binascii.crc32(i)&0xffffffff):
            key = key + i
            print(key)

