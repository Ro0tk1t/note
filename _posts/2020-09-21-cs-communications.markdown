---
layout: post
title:  "程序间的几种通讯方式基本使用"
date:   2020-09-26
categories: Socketio gRPC RESTful GraphQL
---

## `Socketio`  

最初为nodejs使用的一种端到端的通信方式，具有持久连接，掉线自动重连，基于事件驱动等特性。后其他语言也能使用。  
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

`python3`异步版服务端代码如下，同步版写法基本一样：
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


## gRPC  

是 Google 开源的基于 Protobuf 和 Http2.0 协议的通信框架，跨平台跨语言。
Protobuf优势在于灵活高效，由于是二进制数据，所以其占用的内存比类似于xml、json等传统数据格式更小，传输和解析的效率也更高。  

python里使用需要安装三个包`grpcio、protobuf、grpcio_tools`  
protobuf协议文件定义类似如下(dating.proto)：  
```golang
syntax = "proto3";

package date;


service Dating{
    rpc Eating (Eat) returns (Feel){}
    rpc WatchMovie(Movie) returns (Feel){}
}


message Eat{
    string food = 1;
}

message Movie{
    string film = 1;
}

message Feel{
    bool feeling = 1;
}
```
当未定义syntax时回默认使用proto2版本。  
然后编译proto文件:
```bash
python3 -m grpc_tools.protoc -I . --python_out=. --grpc_python_out=. dating.proto
```
会生成dating_pb2.py和dating_pb2_grpc.py的文件，server和client会进行调用。  
要使用包括内嵌消息等高级用法可以看protobuf的 [官方文档](https://developers.google.com/protocol-buffers/docs/proto3)  

接着是服务端相关代码(server.py)：
```python
import grpc
import logging
import dating_pb2
import dating_pb2_grpc

from concurrent import futures


class Servicer(dating_pb2_grpc.DatingServicer):
    def Eating(self, request, context):
        logger.debug(f'[*] we are eating {request.food}')
        return dating_pb2.Feel(feeling=True)

    def WatchMovie(self, request, context):
        logger.debug(f'[*] we are watching 《{request.film}》')
        return dating_pb2.Feel(feeling=True)


def start():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=5))
    dating_pb2_grpc.add_DatingServicer_to_server(Servicer(), server)
    server.add_insecure_port('[::]:6666')
    server.start()
    server.wait_for_termination()

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('us')
logger.setLevel(logging.DEBUG)
start()
```
最后是客户端相关代码(client.py)：
```python
import grpc
import dating_pb2
import dating_pb2_grpc


def start():
    with grpc.insecure_channel('localhost:6666') as channel:
        stub = dating_pb2_grpc.DatingStub(channel)
        eat_feeling = stub.Eating(dating_pb2.Eat(food='steak'))
        film_feeling = stub.WatchMovie(dating_pb2.Movie(film='星际穿越'))
    if eat_feeling.feeling and film_feeling.feeling:
        print('[+]  we think the food and the film is all great.')

start()
```

最后就能server和client通信了。  
grpc也是能跨语言的，缺点就是不同语言得分别生成不同的pb文件去调用，这里保持Python的server端，再使用Golang尝试一下client端：  
先安装go需要的库:  
```bash
sudo apt install -y protobuf-compiler
# 这里需要fq
go get -u google.golang.org/protobuf/cmd/protoc-gen-go
go install google.golang.org/protobuf/cmd/protoc-gen-go
go get -u google.golang.org/grpc/cmd/protoc-gen-go-grpc
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc
```
再生成go版的pb文件，还是使用上面定义的proto文件：
```bash
mkdir date
protoc --go_out=./date/ --go-grpc_out=./date/ --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative dating.proto
```
然后date目录里会出现go版的pb文.  

go版client代码如下（client.go）：
```golang
package main

import (
    "log"
    "context"
    "time"
    "google.golang.org/grpc"
    pb "./date"
)

const (
    address = "localhost:6666"
)

func main(){
    conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithBlock())
    if err != nil{
        log.Fatalf("connection failed. %v", err)
    }
    defer conn.Close()
    c := pb.NewDatingClient(conn)

    ctx, cancel := context.WithTimeout(context.Background(), time.Second)
    defer cancel()
    e, err := c.Eating(ctx, &pb.Eat{Food: "火锅"})
    if err != nil{
        log.Fatalf("failed 2 eat")
    }
    m, err := c.WatchMovie(ctx, &pb.Movie{Film: "盗梦空间"})
    if err != nil{
        log.Fatalf("failed 2 eat")
    }
    if e.Feeling && m.Feeling{
        log.Println("[+]  we think the food and the film is all great.")
    }
}
```

## RESTful

全称为(Representational State Transfer)表现层状态转化  
表现层指资源的表现层，状态转化是指数据的状态和变化转化为HTTP的状态去体现出来。  
所以resetful的总结就是：
> 每个URI就是一种资源  
> 客户端和服务器之间，传递这种资源的某种表现层  
> 客户端通过HTTP方法，对服务器端资源进行操作，实现"表现层状态转化"  

下面通过flask及其restful插件实现一个简单的restful示例  
server.py:
```python
from flask import Flask, request, json
from flask_restful import Api, Resource


app = Flask('rest')
api = Api(app)


tasks = [
    {'id': 1, 'name': 'task1'},
    {'id': 2, 'name': 'task2'},
    {'id': 3, 'name': 'task3'},
]


class Task_(Resource):
    def get(self):
        return tasks


class Task(Resource):
    def get(self, task_id):
        return [task for task in tasks if (lambda task:task['id'] == task_id)(task)]

    def put(self, task_id):
        data = request.form['data']
        task = {'id': task_id}
        task.update(json.loads(data))
        tasks.append(task)
        return task, 201


api.add_resource(Task_, '/tasks')
api.add_resource(Task, '/tasks/<int:task_id>')
app.run(debug=True)
```
由于是通过HTTP方法去操作，所以可以不需要特殊的client，通过浏览器或其他网络连接工具就可以了  
基于上面的示例，直接使用curl去通信了:
```bash
$ curl localhost:5000/tasks
[
    {
        "id": 1,
        "name": "task1"
    },
    {
        "id": 2,
        "name": "task2"
    },
    {
        "id": 3,
        "name": "task3"
    }
]
$ curl localhost:5000/tasks/5 -d 'data={"name": "task5"}' -X PUT -v
*   Trying ::1:5000...
* connect to ::1 port 5000 failed: 拒绝连接
*   Trying 127.0.0.1:5000...
* Connected to localhost (127.0.0.1) port 5000 (#0)
> PUT /tasks/5 HTTP/1.1
> Host: localhost:5000
> User-Agent: curl/7.72.0
> Accept: */*
> Content-Length: 22
> Content-Type: application/x-www-form-urlencoded
>
* upload completely sent off: 22 out of 22 bytes
* Mark bundle as not supporting multiuse
* HTTP 1.0, assume close after body
< HTTP/1.0 201 CREATED
< Content-Type: application/json
< Content-Length: 39
< Server: Werkzeug/1.0.1 Python/3.8.5
< Date: Sat, 26 Sep 2020 03:54:57 GMT
<
{
    "id": "5",
    "name": "task5"
}
* Closing connection 0
$ curl localhost:5000/tasks
[
  {
    "id": 1,
    "name": "task1"
  },
  {
    "id": 2,
    "name": "task2"
  },
  {
    "id": 3,
    "name": "task3"
  },
  {
    "id": 5,
    "name": "task5"
  }
]
```
先获取task列表（三个task），再通过PUT方法增加一个task，再次获取task列表，发现多了一个id为5的task。  

## GraphQL
由Facebook于2015年推出的一种用于 API 的查询语言  
GraphQL 既是一种用于 API 的查询语言也是一个满足你数据查询的运行时。 GraphQL 对你的 API 中的数据提供了一套易于理解的完整描述，使得客户端能够准确地获得它需要的数据，而且没有任何冗余，也让 API 更容易地随着时间推移而演进，还能用于构建强大的开发者工具。  

特点:  
> 需要什么就获取什么数据  
> 支持关系数据的查询  
> API无需定义各种路由，完全数据驱动  
> 无需管理API版本，一个版本持续演进  
> 支持大部分主流开发语言和平台  
> 强大的配套开发工具  

用Koa.js实现一个简单GraphQL服务：  
安装koa相关依赖：  
```bash
npm install koa koa-mount koa-graphql
```
server.js：
```javascript
const Koa = require('koa');
const mount = require('koa-mount');
const graphqlHTTP = require('koa-graphql');

const app = new Koa();


var { buildSchema } = require('graphql');
var GraphQLSchema4People = buildSchema(`
    type Query {
        name: String
        age: Int
        sex: Boolean!
        hobby: [String]
    }
`);

var root = {
    name: () => {
        return 'Rootkit';
    },
    age: () => {
        return 99;
    },
    sex: () => {
        return true;
    },
    hobby: () => {
        return ['Coding', 'Badminton', 'Billiards', 'Reading', 'Guitar'];
    },
}


app.use(mount('/graphql', graphqlHTTP({
    schema: GraphQLSchema4People,
    rootValue: root,
    graphiql: true
})));

app.listen(4444);
```
开启服务监听4444端口:
```bash
node server.js
```
然后访问 `http://localhost:4444/graphql`是一个构建好的GraphQL查询页面，可以直接在这使用查询语法查找需要的数据。  
这里用curl测试查询
```bash
$ curl 'http://localhost:4444/graphql?query=\{name%0Ahobby\}' -H 'Content-Type=apllication/json'
{"data":{"name":"Rootkit","hobby":["Coding","Badminton","Billiards","Reading","Guitar"]}}
```
当然graphql不是只能做查询，增删改查都可以，这里只举例查询。
