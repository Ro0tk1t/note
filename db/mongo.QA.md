- 当字段里既有`list` 又有`bool`、`string`等类型值时，怎么查询结果数组长度为1和2的结果数量？
*可以用`$or`实现：`db.collection.count({$or: [{'result': {$size: 1}}, {'result': {$size: 2}}]})`*

	- 但是要获取数组长度大于2以上的话，再像上面这样操作就很麻烦了。。
有没有更简单的办法呢？
`db.collection.count({'result': {$size: {$gt: 2}}})`
抱歉，理想很美好，但是官方不支持这种操作。

	- 没事儿，还有奇淫技巧：
**db.collection.count({'result.2': {$exists: 1}})**

- mongo里的id字段默认是ObjectId类型，所以当我们需要知道数据更新的时间而记录里并没有存对应的时间字段时
``` mongo shell
> ObjectId("5a5f1468ae3947568cdac96e").getTimestamp()
ISODate("2018-01-17T09:16:24Z")
```
``` ipython
In [1]: import time
In [2]: t = '5a5f1468ae3947568cdac96e'

In [3]: time.localtime(int(t[:8], 16))
Out[3]: time.struct_time(tm_year=2018, tm_mon=1, tm_mday=17, tm_hour=17, tm_min=16, tm_sec=24, tm_wday=2, tm_yday=17, tm_isdst=0)
```