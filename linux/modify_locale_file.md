如何批量就地修改文件中包含某字符的行？
-------------------------------------

> 可以先 grep 出需要修改的文件， 然后再用 sed 挨个文件修改。

```bash
#!/bin/bash

for x in `grep -r -l -I 'source string or regex' ./`
do
  sed -i "s/source string or regex/destination string/g" $x
done
```


文件太大无法打开，怎样就地删除前面的很多行内容?
-----------------------------------------------
```bash
# 删除前1到100000行
sed -i '1,100000d' access.log
```
