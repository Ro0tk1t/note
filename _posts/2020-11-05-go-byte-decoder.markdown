---
layout: post
title:  "go实现字节解码器"
date:   2020-11-05
categories: golang decode byte
---

最近写代码遇到读文件还原原始字节的问题，  
比如有如下文件：
```bash
$cat a.txt
\x05\x04\x00\x01\x02\x80\x05\x01\x00\x03\x0agoogle.com\x00\x50GET / HTTP/1.0\r\n\r\n
```
为了HumanReadable，文件中将不可见字符显示的用\x表示出来，换行符也用\表示出来了，但是实际需要使用的是它最原始的字节。  
用代码从文件读出来时\是会被转义的。  
这个问题用python很容易解决，一行代码就能转换过来：
```python
#!/usr/bin/env python
# coding=utf-8


with open('a.txt') as f:
    data = f.read()

print(data)
print(bytes([ord(x) for x in data.encode().strip().decode('unicode_escape')]))
print(data.encode().strip().decode('unicode_escape'))
print([ord(x) for x in data.encode().strip().decode('unicode_escape')])
```
执行如下:
```bash
$ python3 decode.py 
\x05\x04\x00\x01\x02\x80\x05\x01\x00\x03\x0agoogle.com\x00\x50GET / HTTP/1.0\r\n\r\n

b'\x05\x04\x00\x01\x02\x80\x05\x01\x00\x03\ngoogle.com\x00PGET / HTTP/1.0\r\n\r\n'

google.comPGET / HTTP/1.0


[5, 4, 0, 1, 2, 128, 5, 1, 0, 3, 10, 103, 111, 111, 103, 108, 101, 46, 99, 111, 109, 0, 80, 71, 69, 84, 32, 47, 32, 72, 84, 84, 80, 47, 49, 46, 48, 13, 10, 13, 10]

```

但是我最近切到go了，于是到网上找go的相关实现方式。  
找了半天发现相关问题网友最相关的回答也是 写文件时就写最原始的字节流。。  
好吧。 我淦  
想了想，用strings.Replace()也不是不可以，如果要覆盖ascii范围的话，要 replace 128 次，如果要覆盖utf8范围的话，要replace 0xffff次。  
算了，还是自己手撕解码器吧。
```golang
package main

import (
    "os"
    "fmt"
    "log"
    "strconv"
    "io/ioutil"
)

func main(){
    fd, err := os.Open("a.txt")
    if err != nil {
        log.Fatal(err)
    }
    defer fd.Close()
    data, _ := ioutil.ReadAll(fd)
    fmt.Printf("original bytes from file: %v\n", data)
    fmt.Printf("original strings from file: %v\n", string(data))

    var (
        decode_str []rune
        tmp string
    )
    for _, char := range data {
        if char == '\\' {
            if len(tmp) != 0 {
                if tmp[0] == '\\' {
                    decode_str = append(decode_str, decode(tmp)...)
                } else {
                    for _, t := range tmp {
                        decode_str = append(decode_str, t)
                    }
                }
                tmp = "\\"
            }
            tmp = "\\"
        } else {
            tmp += string(char)
        }
    }

    decode_str = append(decode_str, decode(tmp)...)
    fmt.Printf("decoded bytes: %v\n", decode_str)
    fmt.Printf("decoded strings: %s\n", string(decode_str))
}

func decode(chars string) []rune {
    var result []rune
    switch chars[1]{
    case 'x':
        if len(chars) <= 4 {
            s, err := strconv.ParseUint(chars[2:], 16, 32)
            if err == nil {
                result = append(result, rune(s))
            }
        } else {
            s, err := strconv.ParseUint(chars[2:4], 16, 32)
            if err == nil {
                result = append(result, rune(s))
            }
            for _, x := range chars[4:] {
                result = append(result, x)
            }
        }
    case 'n':
        result = append(result, '\n')
    case 'r':
        result = append(result, '\r')
    case 't':
        result = append(result, '\t')
    }

    if chars[1] != 'x' && len(chars) > 2 {
        for _, x := range chars[3:] {
            result = append(result, x)
        }
    }

    return result
}
```
代码量比python多了n倍。但是海星，主要功能看着没问题   
最终执行结果如下：
```bash
$ go run decode.go
original bytes from file: [92 120 48 53 92 120 48 52 92 120 48 48 92 120 48 49 92 120 48 50 92 120 56 48 92 120 48 53 92 120 48 49 92 120 48 48 92 120 48 51 92 120 48 97 103 111 111 103 108 101 46 99 111 109 92 120 48 48 92 120 53 48 71 69 84 32 47 32 72 84 84 80 47 49 46 48 92 114 92 110 92 114 92 110 10]
original strings from file: \x05\x04\x00\x01\x02\x80\x05\x01\x00\x03\x0agoogle.com\x00\x50GET / HTTP/1.0\r\n\r\n

decoded bytes: [5 4 0 1 2 128 5 1 0 3 10 103 111 111 103 108 101 46 99 111 109 0 80 71 69 84 32 47 32 72 84 84 80 47 49 46 48 13 10 13 10]
decoded strings:
google.comPGET / HTTP/1.0


```
可以看出来解码出来的byte数组和python解出来的一样的
