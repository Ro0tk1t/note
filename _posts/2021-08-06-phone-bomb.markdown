---
title:  "一款电话短信轰炸器"
date:   2021-08-06 21:03:36 +0530
categories: SMS bomb phone
---

## 一款电话短信轰炸器  

手机经常收到各种广告短信验证码短信诈骗短信等乱七八糟的短信。 突然回想起在学校里玩过一款手机轰炸器还挺好玩的，一键轰炸，  
现在已经找不到它了。网上冲浪 找了找现在还有没有能用的，看网上大部分轰炸器都是Python写的，并且还很多还都删库了，剩下的看着都不太好用，于是想用go写一款简单的轰炸器。  
由于很早之前接触linux后就一直崇尚命令行哲学，所以就打算做个纯命令行形式的工具玩。  
画了一个简单的流程图：  

![流程图](/note/assets/bomb.png)

api数据用的yaml格式，可读性好点。其实也可以放数据库里，由于数据量比较少，可以但没有必要这样。  
目前只有一个石墨的接口自测用  

于是花了几天下班后的时间实现了这个简单的轰炸器。  
使用cobra作为命令解析器，无限循环遍历轰炸  
```bash
$ ./bomb --help
Usage:
  bomb [command]

Available Commands:
  completion  generate the autocompletion script for the specified shell
  help        Help about any command
  version     show current version

Flags:
  -a, --areacode string   the phone number area code, example: +86
  -c, --config string     data file
  -d, --delay int         delay bomb between requests
  -h, --help              help for bomb
  -p, --phone string      phone number
```

repo如下： [https://github.com/Ro0tk1t/bomb.git](https://github.com/Ro0tk1t/bomb.git)
