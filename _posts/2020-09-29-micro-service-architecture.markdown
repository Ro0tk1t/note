---
title:  "从单机到分布式集群到微服务架构的实践"
date:   2020-09-29 21:03:36 +0530
categories: MicroArchitecture Distributed
---

## 0x00

想实现一个完备的微服务架构，于是就开始了。

## 0x01

设想应该具备的功能：  
* 主从分布式集群结构  
* 所有节点能互相通信，具有心跳包检测、远程服务调用、http代理、主节点选举功能  
* 任务推送、任务监控、结果推送  
* 子节点同时作为缓存服务器
* 作为系统服务运行  

有点类似OSPF路由的思想  

## 0x02

很好，依据设想画出以下架构图：

![不太完整的架构图](/note/assets/micro.png)


## 0x03

接着开始写gRPC服务(communicate.proto)，主要包含任务类、心跳类、节点选举类rpc。作为示例，就简单的将抓取目标源码作为任务了。  
```golang
syntax = "proto3";

package communicate;

service Tasks{
    rpc GetTask(ID) returns (Task){}
    rpc ListTask(Query) returns (ID){}
    rpc CreateTask(Task) returns (OptResult){}
//    rpc NotifyTask(ID)
    rpc DelTask(ID) returns (OptResult){}
    rpc KillTask(ID) returns (OptResult){}
    rpc GetTaskResult(ID) returns (TaskResult){}
}

message ID{
    repeated string id = 1;
}

message Task{
    string id = 1;
    string name = 2;
    string target = 3;
    // we can change type field 2 enum type when we know exactly what types of tasks are
    string type = 4;
    enum State {
        WAITING = 0;
        INQUEUE = 1;
        RUNNING = 2;
        RUNTIME_ERROR = 3;
        SUCCEED = 4;
        KILLED = 5;
    }
    State state = 5;
    repeated TaskResult results = 6;
}

message TaskResult{
    string code = 1;
}

message Query {
    repeated int32 state = 1;
}

message OptResult{
    map <string, bool> succeed = 1;
}


service HeartBeats{
    rpc IsAlive(HeartBeat) returns (OK){}
    rpc AskAlive(Node) returns (OK){}
}

message OK{
    bool ok = 1;
}

message HeartBeat{
    bool alive = 1;
    string who = 2;
}

message Node{
    string name = 1;
    string token = 2;
    string host = 3;
}


service Elections{
    rpc RequestElection(Secret) returns (OptResult){}
    rpc VerifyNode(Node) returns (OptResult){}
    rpc UpdateSecret(Node) returns (OptResult){}
}

message Election{
    Secret secret = 1;
    Node from = 2;
}

message Secret{
    string sec_code = 1;
}
```
编译下proto文件：  
```bash
$ mkdir communicate
$ protoc --go_out=./communicate/ --go-grpc_out=./communicate/ --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative communicate.proto
```

## 0x04

接着开始做web层的东西，准备用gin和vue做了
web.go:  
```golang
package main

import (
    "os"
    "fmt"
    "log"
    "net/http"
    "context"

    "github.com/go-redis/redis/v8"
    "github.com/satori/go.uuid"
    "github.com/gin-gonic/gin"
    "google.golang.org/grpc"
    pb "../communicate"
    "../conf"
)

var ctx_ = context.Background()
var rdb = redis.NewClient(&redis.Options{
    Addr: conf.RedisAddr,
    Password: conf.RedisPwd,
    DB: conf.RedisDB,
})
var conn, _ = grpc.Dial("localhost:6666", grpc.WithInsecure())
var task_client = pb.NewTasksClient(conn)
type Ids struct{
    Vals []string `json:"ids"`
}

func list_task(c *gin.Context){
    res, err := task_client.ListTask(ctx_, &pb.Query{})
    if err != nil{
        log.Print(err)
    }
    tasks := []pb.Task{}
    for _, id := range res.Id{
        task := rdb.HGetAll(ctx_, id).Val()
        tasks = append(tasks, pb.Task{Id: id, Name: task["name"], State: 1})
    }
    c.HTML(http.StatusOK, "index.html", gin.H{
        "title": "Task center",
        "tasks": tasks,
        "total": len(tasks),
    })
}

func create_task(c *gin.Context){
    name := c.PostForm("name")
    target := c.PostForm("target")
    if name == "" || target == ""{
        c.HTML(200, "create_task.html", gin.H{
            "title": "Create Task",
            "err_msg": "name and target is required !",
        })
    } else {
        var task pb.Task
        task.Name = name
        task.Target = target
        task.State = 0
        task.Type = c.PostForm("type")
        id, err := uuid.NewV4()
        if err != nil {
            fmt.Printf("Something went wrong: %s", err)
            return
        }
        task.Id = fmt.Sprintf("%s", id)
        res, err := task_client.CreateTask(ctx_, &task)
        fmt.Printf("%v\n", res)
        if err != nil{
            log.Print(err)
        }
        c.HTML(200, "create_task.html", gin.H{
            "title": "Create Task",
        })
    }
}

func del_task(c *gin.Context){
    ids := Ids{}
    c.BindJSON(&ids)
    var ids_ pb.ID
    for _, id := range ids.Vals{
        ids_.Id = append(ids_.Id, id)
    }
    res, err := task_client.DelTask(ctx_, &ids_)
    if err != nil{
        log.Print(err)
    }
    c.JSON(200, res.Succeed)
}

func main(){
    r := gin.Default()
    workdir := os.Getenv("WORKDIR")
    r.LoadHTMLGlob(workdir + "templates/*")
    r.Static("js", workdir + "js")
    defer conn.Close()
    _ = pb.NewTasksClient(conn)

    r.GET("/index", list_task)
    r.GET("/", list_task)
    r.GET("/create_task", func(c *gin.Context){
        c.HTML(200, "create_task.html", gin.H{
            "title": "Create Task",
        })
    })
    r.POST("/create_task", create_task)
    r.POST("/del_task", del_task)
    r.Run(":8080")
}
```
index.html:  
```html
<html>
    <head>
    {% raw %}
        {{ block "css.tmpl" . }}{{end}}
        <title>{{ .title }}</title>
    </head>
    <body>
        {{ block "nav.tmpl" . }}{{end}}

        <section class="content" id="showcontent">
    <form method="POST" action="/del_task" id="opt_task">
        <div class="row">
            <div class="col-md-12">
                <div class="box box-primary">
                    <div class="box-header">
                        <h3 class="box-title">任务列表</h3>
                    </div>
                    <div class="box-body table-responsive no-padding">
                        <table class="table table-hover">
                            <tbody>
                            <tr>
                                <th>
                                    <input type="checkbox" id="select_all">  全选/反选
                                </th>
                                <th>ID</th>
                                <th>任务名</th>
                                <th>状态</th>
                            </tr>
                            {{ range $i, $task := .tasks }}
                            <tr>
                                <td id="{{ $task.Id }}">
                                    <input type="checkbox" class="custom-control-input"
                                           name="box" v-model="task" value='{{$task.Id}}' />
                                </td>
                                <td class="td_bd">
                                    <a href="#"> {{$task.Id}} </a>
                                </td>
                                <td> {{ $task.Name }} </td>
                                <td> {{ $task.State }} </td>
                            </tr>
                            {{ end }}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
        <h3>总任务: <b id="sum"> {{ .total }} </b></h3>
        <a href="#" class="btn btn-primary" role="button" id="stop" name="buy_or_del">
            <span class="glyphicon glyphicon-ok"></span> 停止任务</a>&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp
        <a href="" class="btn btn-danger" role="button" @click="del([[task]])">
            <span class="glyphicon glyphicon-trash" ></span> 删除任务</a>
    </form>
</section>

        {{ block "footer.tmpl" . }}{{end}}
        <script src="js/tasks.js"></script>
    </body>
    {% endraw %}
</html>
```
tasks.js:  
```javascript
Vue.createApp({
    delimiters: ['[[', ']]'],
    data(){
        return {
            task: []
        }
    },
    methods: {
        del(task){
            axios.post('/del_task', {
                ids: this.task
            }).then(function(res){
                var data = res.data;
                for (id in data){
                    if (data[id]){
                        console.log('deleted '+id);
                    } else {
                        console.log('failed 2 delete '+id);
                    }
                }
            }).catch(function(err){
                console.log(err);
            });
        },

        select_all(){
            // TODO
        }
    }
}).mount('#opt_task');
```
哇~， 前后端通讯好麻烦，遇到一堆问题。。。 
先是vue的app挂载不上DOM节点，后来将vue的script放在body最下面解决  
然后是axios不能发起post请求，发现一是修改js代码后没刷新浏览器缓存，二是使用了未定义数据，三是点击事件绑定的DOM节点绑错了。。。
然后修改绑定节点，使用this获取数据，刷新本地缓存，才看到post过来  

接着虽然请求发出了，但是gin并没有收到想要数据，查了半天也没找到哪里出问题了，
查了gin的文档，切换Form和FormArray都拿不到数据。没办法只有用大杀器wireshark抓包了，发现axios传过来的数据是json并且想要的数据还嵌套了几层，
所以让gin绑定json结构体去获取数据，切换vue的点击事件方法调用为原生js的方法调用，解决。  

## 0x05

接着写grpc的Server端，数据相关就直接用redis搞了(server.go)：  
```golang
package main

import (
    "log"
    "net"
    "context"

    "google.golang.org/grpc"
    pb "../communicate"
    "../conf"
    "../utils"
)

var ctx_ = context.Background()

type Task map[string]interface{}

type TaskServer struct{
    *pb.UnimplementedTasksServer
}

func (s *TaskServer) GetTask(ctx context.Context, id *pb.ID) (*pb.Task, error){
    // TODO:
    // find task from redis or mongo
    return &pb.Task{}, nil
}
func (s *TaskServer) ListTask(ctx context.Context, query *pb.Query) (*pb.ID, error){ // TODO:
    var task_ids pb.ID
    if query.State == nil{
        keys := conf.Rdb.Keys(ctx_, "*").Val()
        for _, key := range keys{
            //task := conf.Rdb.HGetAll(ctx_, key).Val()
            task_ids.Id = append(task_ids.Id, key)
        }
    }
    return &task_ids, nil
}

func (s *TaskServer) CreateTask(ctx context.Context, task *pb.Task) (*pb.OptResult, error){
    var result pb.OptResult
    id := task.Id
    if err := conf.Rdb.HMSet(ctx_, id, "id", id, "name", task.Name, "Target", task.Target, "type", task.Type, "state", int32(task.State)).Err(); err != nil{
        return &result, err
    }
    if que := utils.GetMinQue(); que != ""{
        go utils.PushTask(que, id)
    }
    result.Succeed = make(map[string]bool)
    result.Succeed[id] = true
    return &result, nil
}

func (s *TaskServer) DelTask(ctx context.Context, id *pb.ID) (*pb.OptResult, error){
    var result pb.OptResult
    result.Succeed = make(map[string]bool)
    for _, id := range id.Id{
        if err := conf.Rdb.Del(ctx_, id).Err(); err == nil{
            result.Succeed[id] = true
        } else {
            result.Succeed[id] = false
            log.Printf("%v", err)
        }
    }
    return &result, nil
}

func (s *TaskServer) KillTask(ctx context.Context, id *pb.ID) (*pb.OptResult, error){
    // TODO:
    return &pb.OptResult{}, nil
}

func (s *TaskServer) GetTaskResult(ctx context.Context, id *pb.ID) (*pb.TaskResult, error){
    // TODO:
    return &pb.TaskResult{}, nil
}

type HeartBeatServer struct{
    *pb.UnimplementedHeartBeatsServer
}

func (s *HeartBeatServer) IsAlive (ctx context.Context, hb *pb.HeartBeat)(*pb.OK, error){
    return &pb.OK{}, nil
}

func (s *HeartBeatServer) AskAlive (ctx context.Context, node *pb.Node)(*pb.OK, error){
    var ok pb.OK
    // TODO: varify
    ok.Ok = true
    return &ok, nil
}

type ElectionServer struct{
    // TODO:
    *pb.UnimplementedElectionsServer
}

func (s *ElectionServer) RequestElection(ctx context.Context, secret *pb.Secret)(*pb.OptResult, error){
    // TODO:
    return &pb.OptResult{}, nil
}

func (s *ElectionServer) VerifyNode(ctx context.Context, node *pb.Node)(*pb.OptResult, error){
    // TODO:
    return &pb.OptResult{}, nil
}

func (s *ElectionServer) UpdateNode(ctx context.Context, node *pb.Node)(*pb.OptResult, error){
    // TODO:
    return &pb.OptResult{}, nil
}


func main(){
    lis, err := net.Listen("tcp", ":6666")
    if err != nil{
        log.Fatalf("failed 2 listen :6666")
    }
    s := grpc.NewServer()
    pb.RegisterTasksServer(s, &TaskServer{})
    pb.RegisterHeartBeatsServer(s, &HeartBeatServer{})
    pb.RegisterElectionsServer(s, &ElectionServer{})
    go utils.Work()
    go utils.HandlePublic()
    go utils.ImAlive()
    go utils.WillUDie()
    s.Serve(lis)
}
```
settings.go :
```golang
package conf

import (
    "os"
    "fmt"
    "log"
    "io/ioutil"
    "encoding/json"
    "github.com/go-redis/redis/v8"
    "google.golang.org/grpc"
    pb "../communicate"
)

type Node struct{
    Host string
    Port int32
    MaxTask int32
    Name string
    Alive bool
    Token string
}

type Config struct{
    RedisAddr string `json:"RedisAddr"`
    RedisPwd string `json:"RedisPwd"`
    RedisDB int `json:"RedisDB"`
    LocalHost string `json:"LocalHost"`
    Token string `json:"Token"`
    Master string `json:"Master"`
}

var (
    RedisAddr = "localhost:6379"
    RedisPwd = ""
    RedisDB = 2
    TaskQue = "tasks"

    Rdb *redis.Client
)

var (
    Name = "master"
    Master = "127.0.0.1"
    NodeType = "master"
    LocalHost = "127.0.0.1"
    Token = "098f6bcd4621d373cade4e832627b4f6"
    HeartBeatGAP int = 60
    RPCDefaultPort int32 = 6666

    GrpcConns = make(map[string] interface {})
    TaskStubs = make(map[string] interface {})
    HeartStubs = make(map[string] interface {})
    ElectionStubs = make(map[string] interface {})
    Nodes = map[string] Node {
        "172.17.0.1": Node{
            Host: "172.17.0.1",
            Port: 6666,
            MaxTask: 10,
            Name: "node1",
            Alive: true,
            Token: "098f6bcd4621d373cade4e832627b4f6",
        },
        "172.17.0.2": Node{
            Host: "172.17.0.2",
            Port: 6666,
            MaxTask: 10,
            Alive: true,
            Name: "node2",
            Token: "098f6bcd4621d373cade4e832627b4f6",
        },
    }
    PubChannel = "Public"
    PubMsgPrefix = map[string] string {
        "0": "Heart Beat",
        "1": "Request Election",
        "2": "Election Vote",
        "3": "Some other thing",
    }
    TaskChannels = []string{"172.17.0.1", "172.17.0.2",}
)

func init(){
    type_ := os.Getenv("NODETYPE")
    if type_ != ""{
        NodeType = type_
    }

    data_path := os.Getenv("DATA")
    if data_path == ""{
        data_path = "../conf/"
    }
    // load & parse config file
    var config Config
    cf, err := os.Open(data_path + "config.json")
    if err != nil{
        log.Printf("[-] open config file failed !")
        log.Printf("%v", err)
    } else {
        defer cf.Close()
        data, _ := ioutil.ReadAll(cf)
        json.Unmarshal(data, &config)
        Rdb = redis.NewClient(&redis.Options{
            Addr: config.RedisAddr,
            Password: config.RedisPwd,
            DB: config.RedisDB,
        })
        Token = config.Token
        LocalHost = config.LocalHost
        Master = config.Master
    }

    // load & parse node list
    cf, err = os.Open(data_path+"nodes.json")
    if err != nil{
        log.Printf("[-] open node file failed !")
        log.Printf("%v", err)
    } else {
        defer cf.Close()
        data, _ := ioutil.ReadAll(cf)
        json.Unmarshal(data, &Nodes)
    }

    for host, node := range Nodes{
        conn, err := grpc.Dial(fmt.Sprintf("%s:%v", host, node.Port), grpc.WithInsecure())
        if err != nil{
            log.Printf("[-] error: can not connect to %s:%v\n", host, node.Port)
        } else {
            GrpcConns[host] = conn
            task_client := pb.NewTasksClient(conn)
            TaskStubs[host] = task_client
            heart_client := pb.NewHeartBeatsClient(conn)
            HeartStubs[host] = heart_client
            election_client := pb.NewElectionsClient(conn)
            ElectionStubs[host] = election_client
        }
    }
}
```

ok，任务主体功能下发删除算是搞定了。  
单机可以正常跑起来了   
gin的web服务与grpc的server通讯，然后集群间也通过grpc通讯。   

然后是grpc的client端：
```golang
```
好吧，突然想起来client已经内置在gin层了。。。   

这里主要功能点是：  
* 每个节点都会读取json配置文件
* 集群中只能有一台master，其他需要为slave，节点会从NODETYPE环境变量中确定自己是什么类型，这里是为了方便配合打docker镜像使用
* 每个节点都订阅以自己host命名的信道，用于收取任务
* 配置中预留了一个Public信道

## 0x06

本来心跳相关也准备用grpc做的，结果发现grpc不能实现广播。啊，难受  
不得已只能暂时用redis的publish功能曲线救国了-_-  
这里正好可以用上面预留的Public信道实现,有先见之明 哈哈哈  

心跳功能差不多了(heart.go)：  
```golang
package utils

import (
    "fmt"
    "log"
    "time"
    "sync"
    "errors"
    "encoding/json"

    "google.golang.org/grpc"
    pb "../communicate"
    "../conf"
)

type Beat struct{
    Host string
    Name string
}

var (
    deadline = make(map[string]int32)
    m = sync.Mutex{}
)

func init(){
    for _, node := range conf.Nodes{
        deadline[node.Host] = 10
    }
}

func ImAlive(){
    for {
        msg := Beat{
            Host: conf.LocalHost,
            Name: conf.Name,
        }
        msg_, _ := json.Marshal(msg)
        conf.Rdb.Publish(ctx, conf.PubChannel, "0:"+string(msg_))
        log.Printf("[*] I'm beating")
        time.Sleep(time.Duration(conf.HeartBeatGAP) * time.Second)
    }
}

func HeardPeopleBeating(msg string){
    var beat Beat
    if err := json.Unmarshal([]byte(msg), &beat); err != nil{
        log.Printf("[-] invalid heart beat message")
    } else if beat.Host != conf.LocalHost{
        log.Printf("[*] heard %v's heart beat", beat.Name)
        UpdateNodes(beat)
    }
}

func UpdateNodes(beat Beat){
    is_known_node := false
    for _, node := range conf.Nodes{
        if node.Host == beat.Host{
            node.Alive = true
            is_known_node = true
            m.Lock()
            if deadline[beat.Host] < 10{
                deadline[beat.Host] ++
            }
            m.Unlock()
        }
    }
    if !is_known_node{
        go ValidateNode(beat)
    }
}

func ValidateNode(beat Beat){
    TryEstablish(beat)
}

func TryEstablish(beat Beat){
    host := beat.Host
    conn, err := grpc.Dial(fmt.Sprintf("%s:%v", host, conf.RPCDefaultPort), grpc.WithInsecure())
    if err != nil{
        log.Printf("[-] warning: %s is not a node.", host)
    } else {
        heart_client, err := AskWhoUAre(conn, beat)
        if err == nil{
            conf.GrpcConns[host] = conn
            conf.HeartStubs[host] = heart_client
            task_client := pb.NewTasksClient(conn)
            conf.TaskStubs[host] = task_client
            election_client := pb.NewElectionsClient(conn)
            conf.ElectionStubs[host] = election_client

            var node conf.Node
            node.Host = host
            node.Name = beat.Name
            node.Port = conf.RPCDefaultPort
            node.Alive = true
            conf.Nodes[host] = node
        } else {
            defer conn.Close()
        }
    }
}

func AskWhoUAre(conn *grpc.ClientConn, beat Beat) (pb.HeartBeatsClient, error){
    heart_client := pb.NewHeartBeatsClient(conn)
    var node pb.Node
    node.Name = beat.Name
    node.Host = beat.Host
    res, err := heart_client.AskAlive(ctx, &node)
    if err == nil && res.Ok{
        return heart_client, nil
    }
    return nil, errors.New("node is illegal")
}

func WillUDie(){
    for {
        time.Sleep(time.Duration(conf.HeartBeatGAP) * time.Second)
        for _, node := range conf.Nodes{
            m.Lock()
            deadline[node.Host] --
            m.Unlock()
            if deadline[node.Host] <= 0{
                log.Printf("[-] warning: %v is dead!", node.Host)
                delete(conf.Nodes, node.Host)
                delete(deadline, node.Host)
                IsMasterDead(node)
            }
        }
    }
}

func IsMasterDead(node conf.Node){
    if node.Host == conf.Master{
        ReqElection()
    }
}
```
* 每分钟心跳一次  
* 当收到的心跳不属于已知节点时，做节点验证，验证通过则追加到已知节点列表
* 当十分钟后还没听到已知节点的心跳时，主动验证该节点是否还活着并判断是否移出节点列表

## 0x07
啊，go写的好累。歇会儿，换docker玩玩。。  
基于ubuntu做个镜像（Dockerfile）,这里先提前用go build构建了web和rpc的程序
```docker
FROM ubuntu

WORKDIR /work/
ENV WORKDIR /work/
ENV GOPATH /root/go
ENV NODETYPE slave
ENV DATA /data/

RUN apt update
RUN DEBIAN_FRONTEND=noninteractive apt install -y tzdata
# RUN apt install -y golang-1.14 && ln -s /usr/lib/go-1.14/bin/go /usr/bin/go
RUN apt install -y vim iproute2 wget curl redis-server git &&\
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN mkdir -p ${WORKDIR} ${DATA}

COPY conf/*.json ${DATA}
COPY rpc/rpc web run.sh ${WORKDIR}
COPY conf/redis.conf /etc/redis/redis.conf

EXPOSE 8080
ENTRYPOINT ["sh", "/work/run.sh"]
```
刚开始构建镜像后发现rpc程序一直报空指针的错导致容器一直起不来，后来想到应该是redis没加  
然后加了redis-server后用RUN service redis-server start也起不来redis  
最后想到镜像只是一个文件系统，服务起来只是一个运行时，应该在容器起来时拉起redis  
所以包裹了一层bash：
```bash
#!/bin/bash

service redis-server start
/work/web &
/work/rpc 
```
构建镜像
```bash
$ sudo docker build -t micro:arch --no-cache .
$ sudo docker run -d -p 8080:8080 image_id
$ sudo docker logs container_id
```
web程序运行就直接panic，说是找不到静态文件加载，
关键是第一次运行是是可以正常加载运行的，就吃个饭的功夫，重启就加载不上了，期间也没修改过哪里的环境和代码，就很神奇。  
然后用WORKDIR加资源的路径做绝对路径加载  

OK, 完美运行！

## 0x08

再用docker-compose搭个集群试试（docker-compose.yml）：
```yaml
version: "3"
services:
  master:
    image: "micro:arch"
    environment:
      - NODETYPE=master
    container_name: master
    ports:
      - "8080:8080"
    expose:
      - "6666"
    volumes:
      - "./conf:/data"
  slave1:
    image: micro:arch
    container_name: slave1
    depends_on: 
      - master
    environment:
      - NODETYPE=slave
    ports:
      - "8081:8080"
    expose:
      - "6666"
    volumes:
      - "./conf:/data"
  slave2:
    image: micro:arch
    container_name: slave2
    depends_on: 
      - master
    environment:
      - NODETYPE=slave
    ports:
      - "8082:8080"
    expose:
      - "6666"
    volumes:
      - "./conf:/data"
```
想要几台子节点都可以继续扩展，但是扩展的同时不能让端口冲突，相关配置文件也得改  
需要注意的是compose是python的一个库
```bash
$ pip3 install docker-compose
$ docker-compose up -d
```
根据yaml文件我这里起了三台  

## 0x09

然后突然想起来各节点都是用的自己的redis，需要所有节点都连到主节点redis才行。  
于是修改本机redis.conf绑定到全网，通过dockerfile COPY进去，发现配置文件不兼容，跑不起来--  
好吧，那就用sed实时修改配置吧
```bash
RUN sed -i "s/^bind 127.0.0.1 ::1$/bind 0.0.0.0 ::1/" /etc/redis/redis.conf
```
重新构建镜像，起docker compose  
共用后数据都相通了

## 0x10

然后得用nginx搞个反向代理，文件名随便取，后缀是conf的，如果不是conf后缀得在nginx默认配置文件里include your/conf/file  
/etc/nginx/conf.d/a.conf
```javascript
server {
    listen 81;
    server_name master;
    index index index.html;
    location /* {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header Source-IP $remote_addr;
    }
}
```
这里代理到了81端口  

## 0x11

这里是程序运行需要加载的配置文件  
config.json:  
```javascript
{
  "LocalHost": "127.0.0.1",
  "Token": "098f6bcd4621d373cade4e832627b4f6",
  "RedisAddr": "127.0.0.1:6379",
  "RedisPwd": "",
  "RedisDB": 2,
  "Master": "master"
}
```
nodes.json
```javascript
{
  "slave1": {
    "Host": "slave1",
    "Port": 6666,
    "MaxTask": 10,
    "Name": "node1",
    "Alive": true,
    "Token": "098f6bcd4621d373cade4e832627b4f6"
  },
  "slave2": {
    "Host": "slave2",
    "Port": 6666,
    "MaxTask": 10,
    "Alive": true,
    "Name": "node2",
    "Token": "098f6bcd4621d373cade4e832627b4f6"
  }
}
```
