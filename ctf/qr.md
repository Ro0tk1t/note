实验吧的一道杂项题
-----------------------
[http://ctf5.shiyanbar.com/423/misc/code.txt](http://ctf5.shiyanbar.com/423/misc/code.txt) 

打开后是很长一段字符串，滑到最后是两个等号，所以先base64解码一下，解码出来的结果全是 0 和 1 ，并且长度是 65536=256**2，可以想到是一个长宽都是256的二维码图片，把 0 作为白色，1 作为黑色写图片就行了，直接上代码：

```
#!/usr/bin/env python
# coding=utf-8

import requests
import base64
from PIL import Image
import numpy as np

url = 'http://ctf5.shiyanbar.com/423/misc/code.txt'
req = requests.get(url)
codes = base64.b64decode(req.text).decode()

num = np.array(list(codes))
num_reshaped = num.reshape(256,256)
qr = Image.new('RGB', (256,256))
white = (255,255,255)
black = (0,0,0)
for i in range(256):
    for j in range(256):
        if num_reshaped[i][j] == '0':
            qr.putpixel((i, j), white)
        else:
            qr.putpixel((i, j), black)

qr.save('qr.png')
```

然后同级目录下就会出现一张二维码，扫扫就能得到 flag 了
