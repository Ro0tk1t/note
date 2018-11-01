- 当字段里既有`list` 又有`bool`、`string`等类型值时，怎么查询结果数组长度为1和2的结果数量？
*可以用`$or`实现：`db.collection.count({$or: [{'result': {$size: 1}}, {'result': {$size: 2}}]})`*

但是要获取数组长度大于2以上的话，再像上面这样操作就很麻烦了。。
有没有更简单的办法呢？

`db.collection.count({'result': {$size: {$gt: 2}}})`

抱歉，理想很美好，但是官方不支持这种操作。

没事儿，还有奇淫技巧：
**db.collection.count({'result.2': {$exists: 1}})**