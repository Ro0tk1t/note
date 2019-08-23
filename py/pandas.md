* 如何找出两个`csv`文件里某列里元素相同的行

```python
import pandas as pd

# load csv file
df1 = pd.read_csv('data1.csv')
df2 = pd.read_csv('data2.csv')

# find same
same_df = df2[df2['name'].isin(df1['name'])]
same_df.to_excel('result.xls')

# find different
diff_df = df2[~df2['name'].isin(df1['name'])]
diff_df.to_excel('result.xls')
```
