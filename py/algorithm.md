* 冒泡排序
``` python
num = [4, 7, 3, 9, 1, 10, 6, 8, 2, 5]

for i in range(len(num)-1): 
    for j in range(len(num)-1): 
        if num[j] > num[j+1]: 
            num[j], num[j+1] = num[j+1], num[j]

```

* 选择排序

``` python
num = [4, 7, 3, 9, 1, 10, 6, 8, 2, 5]

for x in range(len(num)):
    m = num[x]
    found = 0
    for y in range(x, len(num)): 
        if num[y] < m: 
            i = y 
            found = 1 
            m = num[y] 
    if found: 
        num[x], num[i] = m, num[x]
```

* 插入排序算法

``` python
num = [4, 7, 3, 9, 1, 10, 6, 8, 2, 5]

for x in range(1, len(num)):
    y_ = None
    v = num[x]
    for y in list(range(x))[::-1]:
        if num[y] > v:
            y_ = y
    if y_ is not None:
        num.pop(x)
        num.insert(y_, v)
```

* 希尔排序

``` python

```
