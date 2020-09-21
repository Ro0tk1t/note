---
layout: post
title:  "程序间几种通讯方式基本使用"
date:   2020-09-21
categories: socketio gRPC restful jsonp
---

`Socketio`, 最初为nodejs使用的一种端到端的通信方式，具有持久连接，掉线自动重连，基于事件驱动等特性。后其他语言也能使用。  
其默认自带有`connect`、`message`、`disconnect`等事件。  
使用`event`方法和`on`方法可实现注册事件。  
`emit`方法和`send`方法都可以发送数据，不同的是`emit`方法可以指定任意事件,看源码可以知道`send`方法最终还是调用的emit方法。  
通信时的数据可以是字符串、列表、字典、元组等等数据结构。

`nodejs`版的服务端代码如下：

```javascript
var server = require('http').createServer();
var io = require('socket.io')(server);
io.on('connection', function(client){
  console.log('connected');
  //when get data on message
  client.on('message', function(obj){
	  console.log("get message and return to client...");
	  io.emit('message', {'a':'messagetest'});
	  console.log("login backed...");
  });
  // when get data on login
  client.on('login', function(obj){
	  console.log("get login data and return to client...");
	  io.emit('login', {'a':'logintest'});
	  console.log("login backed...");
  });
  client.on('event', function(data){});
  client.on('disconnect', function(){
    console.log('client disconnected');
  });
});
console.log("server started on port 8080");
server.listen(8080); 
```

`python3`异步版服务端代码如下：
```python
from aiohttp import web

import socketio


sio = socketio.AsyncServer()
app = web.Application()
sio.attach(app)


@sio.event
def connect(sid, environ):
    # 注册connect事件
    print(f'{sid} connected')

@sio.on('msg')
async def msg_func(sid, data):
    # 注册msg事件
    print(f'received {sid}\'s message @ msg event: {data}')
    await sio.send(f'resend {data}')

@sio.event
async def reply(sid, data):
    # 注册reply事件
    print(f'received {data}')
    await sio.emit('reply')

@sio.event
async def message(sid, data):
    print(f'received {sid}\'s message: {data}')

@sio.event
async def disconnect(sid):
    # 注册disconnect事件
    print(f'{sid} disconnected.')


if __name__ =='__main__':
    web.run_app(app)
```

`python3`异步式客户端代码如下：
```python
import asyncio
import socketio


url = 'http://127.0.0.1:8080'

sio = socketio.AsyncClient()

@sio.event
async def connect():
    # 注册connect事件
    print(f'connected 2 {url}')

@sio.event
async def disconnect():
    # 注册disconnect事件
    print(f'disconnect from {url}')

def main():
    loop = asyncio.get_event_loop()

    loop.run_until_complete(sio.connect(url))
    loop.run_until_complete(test(sio, loop))
    loop.run_until_complete(sio.disconnect())


async def test(sio, loop):
    await sio.send('Hello guys. ')
    await sio.send({'msg': 'use message channel 2 send data'})
    await sio.emit('msg', 'use msg channel 2 send data')

if __name__ == '__main__':
    main()
```
