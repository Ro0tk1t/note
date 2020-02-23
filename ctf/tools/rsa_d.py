#!/usr/bin/env python
# coding=utf-8

import argparse
import time


def get_parames():
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', dest='n', type=int)
    parser.add_argument('-e', dest='e', type=int)
    parser.add_argument('-p', dest='p', type=int)
    parser.add_argument('-q', dest='q', type=int)
    parser.add_argument('-d', dest='d', type=int)
    return parser.parse_args()


def get_d(n, e, k=1):
    while 1:
        if k % 100 == 0:
            print(k)
        if (n*k + 1)%e == 0:
            print('d: ', int((n*k + 1)/e))
            break
        k += 1

if __name__ == '__main__':
    parames = get_parames()
    n, p, q, e = parames.n, parames.p, parames.q, parames.e
    if e:
        if n:
            get_d(n, e)
        elif p and q:
            n = (p - 1) * (q - 1)
            get_d(n, e)
