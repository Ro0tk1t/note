实验吧的另一道杂项题
-----------------------
[http://ctf5.shiyanbar.com/misc/Paint_Scan.zip](http://ctf5.shiyanbar.com/misc/Paint_Scan.zip) 
下载 zip 压缩包后打开是一个 txt 文件，查看 txt 内容发现里面是一个二元元组列表，长度 35316，于是猜测列表里每个元素都代表图片里的一个位置，且长和宽都不超过 270 。出现过的位置的就设置为白色。
分析完成，上代码：

```python
#!/usr/bin/env python
# coding=utf-8

from ast import literal_eval
from PIL import Image

qr = Image.new('RGB', (271,271))
white = (255,255,255)
with open('Paint&Scan.txt') as f:
    content = f.read()
    locations = [literal_eval(x) for x in content.splitlines()]

for x in locations:
    qr.putpixel(x, white)

qr.save('paint.png')
```

运行得到一张二维码，不过是反色的，做一遍 xor 就能得到一张正常的二维码，扫码得到 flag
