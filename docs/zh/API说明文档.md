# QuecPython SNMP API说明文档

该模块包含访问snmp库的高级函数



## 通用结构体对象

### BulkResult

> br = **BulkResult(scalars, repeating_out )**

| 参数          | 类型                                  | 说明                         |
| ------------- | ------------------------------------- | ---------------------------- |
| scalars       | dict(X690.ObjectIdentifier=X690.Type) | dict里面包含oid和value的映射 |
| repeating_out | list(varbind)                         | varbind的集合列表            |

#### 获取scalars

```python
br.scalars
```



#### 获取repeating_out

> br.repeating_out



### VarBind

> vb = VarBind(oid, value)

| 参数  | 类型                  | 说明                      |
| ----- | --------------------- | ------------------------- |
| oid   | X690.ObjectIdentifier | X690.ObjectIdentifier对象 |
| value | x690.types            | x690.types对象            |



#### 获取oid

```python
oid = vb.oid
# 获取原始值
oid.value()
```



#### 获取value

```python
v = vb.value
# 获取原始值
v.value()
```





## Client

type：`object`

在远程设备上执行 SNMP 命令的客户端。

要在远程设备上运行 SNMP 命令，请为该设备创建一个实例，然后调用实例方法。

凭据需要是从中获取的类的实例，用于确定此客户端实例的适当通信模型。

>**Client(ip, credentials, port=161, sender=udp_send, context_name=b"", engine_id=b"")**

- 参数

| 参数         | 类型     | 是否必须(Y/N) | 说明                                                      |
| ------------ | -------- | ------------- | --------------------------------------------------------- |
| ip           | str      | Y             | 远程 SNMP 设备的 IP 地址                                  |
| credentials  | V2C      | Y             | 请求的用户凭据。这些定义了正在使用的底层协议              |
| port         | int      | N(默认161)    | 远程设备的 UDP 端口                                       |
| sender       | function | N             | 可用于外部替换udp实现                                     |
| context_name | bytes    | N             | SNMPv3 请求的可选上下文(暂不支持V3)                       |
| engine_id    | bytes    | N             | SNMPv3 请求的可选引擎 ID。提供了帮助函数来生成有效的 ID。 |

使用

```python
from usr.snmp_api import Client, V2C
from usr.snmp_api import ObjectIdentifier as OID

client = Client("220.180.239.212", V2C("public"), port=9654)
```



### V3

V3版本提供客户端加密和认证套件,  目前加密缺少算法, 支持认证, 认证需要在Client初始化的时候指定, 举例

```python
from usr.snmp_common import Auth, Priv
from usr.snmp_api import Client, V2C, OctetString, V3
from usr.snmp_api import ObjectIdentifier as OID

# 只认证, 不加密
client = Client("220.180.239.212", V3("ftt", auth=Auth(b'auth123456', "md5")), port=9654)
output = client.get("1.3.6.1.2.1.1.1.0")

# 加密加认证
client = Client("220.180.239.212", V3("ftt", auth=Auth(b'auth123456', "md5"), priv=Priv(b'priv123456', "aes")), port=9654)
output = client.get("1.3.6.1.2.1.1.1.0")
```

- V3参数

| 参数     | 类型 | 说明                                                         |
| -------- | ---- | ------------------------------------------------------------ |
| username | str  | 用户名这里测试使用ftt                                        |
| auth     | Auth | 认证Auth(key, crypt)  <br>key需要是byte类型<br>认证方式需要是str类型目前支持(md5, sha1)进行加密 |
| priv     | Priv | 加密Priv(key, crypt)<br>key需要加密的byte类型<br>加密方式需要是str类型目前支持(aes, des)进行加密 |





### get

检索单个 OID 的值

> **client.get(oid)**

- 参数

| 参数 | 类型             | 是否必须(Y/N) | 说明                       |
| ---- | ---------------- | ------------- | -------------------------- |
| oid  | ObjectIdentifier | Y             | 包含应作为单个值获取的 OID |



### multiget

在一个请求中从多个 OID 中检索（标量）值。

> **client.multiget(oids)**

| 参数 | 类型                   | 是否必须(Y/N) | 说明                       |
| ---- | ---------------------- | ------------- | -------------------------- |
| oids | List(ObjectIdentifier) | Y             | 包含应作为单个值获取的 OID |

使用

```python
from usr.snmp_api import Client, V2C
from usr.snmp_api import ObjectIdentifier as OID

client = Client("127.0.0.1", V2C("private"), port=50009)
result = client.multiget(
    [OID('1.3.6.1.2.1.1.2.0'), OID('1.3.6.1.2.1.1.1.0')]
)

```





### **getnext**

执行单个 SNMP GETNEXT 请求（在*walk*中使用）。

> **client.getnext(oid)**

- 参数

| 参数 | 类型             | 是否必须(Y/N) | 说明                       |
| ---- | ---------------- | ------------- | -------------------------- |
| oid  | ObjectIdentifier | Y             | 包含应作为单个值获取的 OID |

- 返回值
  - Varbind对象

使用

```python
client = Client("220.180.239.212", V2C("public"), port=9654)
# The line below needs to be "awaited" to get the result.
# This is not shown here to make it work with doctest
coro = client.getnext(OID('1.2.3.4'))
print(coro)
# coro= VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.1.1.0), value=OctetString(value = b'Linux localhost.localdomain 3.10.0-1127.el7.x86_64 #1 SMP Tue Mar 31 23:36:51 UTC 2020 x86_64'))
```







### multigetnext

执行单个 multi-oid GETNEXT 请求。

该请求向远程主机发送一个数据包，请求一个或多个给定 OID 之后的 OID 值。

> **client.multigetnext(oids)**

| 参数 | 类型                   | 是否必须(Y/N) | 说明                       |
| ---- | ---------------------- | ------------- | -------------------------- |
| oids | List(ObjectIdentifier) | Y             | 包含应作为单个值获取的 OID |

- 返回值
  - Varbind对象集合

使用

```python
from usr.snmp_api import Client, V2C, OctetString
from usr.snmp_api import ObjectIdentifier as OID

client = Client("220.180.239.212", V2C("public"), port=9654)
result = client.multigetnext([OID('1.3.6.1.2.1.1.2.0'), OID('1.3.6.1.2.1.1.1.0')])

# result = [VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.1.3.0), value=TimeTicks(value = 10932803)), VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.1.2.0), value=ObjectIdentifier(value = 1.3.6.1.4.1.8072.3.2.10))]
```





### bulkget

运行“批量”获取操作并返回一个`BulkResult`实例。这包含标量变量（“非重复者”）的映射和包含剩余列表（“重复者”）的 List实例。

List的排序方式与 SNMP 响应相同（无论远程设备返回什么）。

此操作可以在一个请求中检索单个/标量值*和值列表（“重复值”）。*例如，您可以在一个请求中检索主机名（一个标量值）、接口列表（一个重复值）和物理实体列表（另一个重复值）。

请注意，这就像对标量值的**getnext**请求一样！因此，您将收到 OID 的值，它*紧跟*在您为标量值和重复值指定的 OID 之后！

> **client.bulkget(scalar_oids, repeating_oids, max_list_size=1)**

| 参数           | 类型                   | 是否必须(Y/N) | 说明                       |
| -------------- | ---------------------- | ------------- | -------------------------- |
| scalar_oids    | list(ObjectIdentifier) | Y             | 包含应作为单个值获取的 OID |
| repeating_oids | list(ObjectIdentifier) | Y             | 包含应作为列表获取的 OID   |
| max_list_size  | int                    | N(默认1)      | 定义每个列表的最大长度     |

使用

```python
from usr.snmp_api import Client, V2C, OctetString
from usr.snmp_api import ObjectIdentifier as OID


client = Client("220.180.239.212", V2C("public"), port=9654)
result = client.bulkget(
    scalar_oids=[
        OID('1.3.6.1.2.1.1.1'),
        OID('1.3.6.1.2.1.1.2'),
    ],
    repeating_oids=[
        OID('1.3.6.1.2.1.3.1'),
        OID('1.3.6.1.2.1.5.1'),
    ],
    max_list_size=10
)

"""
result =BulkResult(
	scalars={ObjectIdentifier(value = 1.3.6.1.2.1.1.2.0): ObjectIdentifier(value = 1.3.6.1.4.1.8072.3.2.10), ObjectIdentifier(value = 1.3.6.1.2.1.1.1.0): OctetString(value = b'Linux localhost.localdomain 3.10.0-1127.el7.x86_64 #1 SMP Tue Mar 31 23:36:51 UTC 2020 x86_64')}, 
	listing=[
	VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.3.1.1.1.2.1.10.0.2.2), value=Integer(value = 2)), VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.5.1.0), value=Counter(value = 0)), VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.3.1.1.1.2.1.10.0.2.3), value=Integer(value = 2)), VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.5.2.0), value=Counter(value = 0)), VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.3.1.1.1.3.1.192.168.56.1), value=Integer(value = 3)), VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.5.3.0), value=Counter(value = 0)), VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.3.1.1.2.2.1.10.0.2.2), value=OctetString(value = b'RT\x00\x125\x02')), VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.5.4.0), value=Counter(value = 0)), VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.3.1.1.2.2.1.10.0.2.3), value=OctetString(value = b'RT\x00\x125\x03')), VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.5.5.0), value=Counter(value = 0)), VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.3.1.1.2.3.1.192.168.56.1), value=OctetString(value = b"\n\x00'\x00\x00\x08")), VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.5.6.0), value=Counter(value = 0)), VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.3.1.1.3.2.1.10.0.2.2), value=IpAddress(value = b'10.0.2.2')), VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.5.7.0), value=Counter(value = 0)), VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.3.1.1.3.2.1.10.0.2.3), value=IpAddress(value = b'10.0.2.3')), VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.5.8.0), value=Counter(value = 0)), VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.3.1.1.3.3.1.192.168.56.1), value=IpAddress(value = b'192.168.56.1')), VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.5.9.0), value=Counter(value = 0)), VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.4.1.0), value=Integer(value = 2)), VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.5.10.0), value=Counter(value = 0))])
"""

```

返回值类型

- BulkResult类型



### set

更新远程主机上的值

值必须是 的子类`x690.types.Type`。请参阅 [`x690.types`](https://exhuma.github.io/x690/api/x690.html#module-x690.types)预定义的类型集合。

> **client.set(oid, value)**

- 参数

| 参数  | 类型             | 是否必须(Y/N) | 说明                       |
| ----- | ---------------- | ------------- | -------------------------- |
| oid   | ObjectIdentifier | Y             | 包含应作为单个值获取的 OID |
| value | X690Type         | Y             | 值类型                     |

- 返回值
  - 设置的value



### multiset

对多个 OID 执行 SNMP SET 请求。结果作为纯 Python 数据结构返回。

> **client.multiset(mappings)**

- 参数

| 参数    | 类型 | 是否必须(Y/N) | 说明        |
| ------- | ---- | ------------- | ----------- |
| mapping | dict | Y             | {oid:value} |

使用

```python
from usr.snmp_api import Client, V2C, OctetString
from usr.snmp_api import ObjectIdentifier as OID


client = Client("220.180.239.212", V2C("public"), port=9654)
coro = client.multiset({
    OID('1.3.6.1.2.1.1.4.0'): OctetString(b'new-contact'),
    OID('1.3.6.1.2.1.1.6.0'): OctetString(b'new-location')
})
# coro 返回值 {ObjectIdentifier('1.3.6.1.2.1.1.4.0'): OctetString(b'contact'), OID('1.3.6.1.2.1.1.6.0'): OctetString(b'new-location')}
```





### walk

`multiwalk()`一种仅使用一个 OID委托给的便捷方法

> **client.walk(oid)**

- 参数

| 参数 | 类型             | 是否必须(Y/N) | 说明                       |
| ---- | ---------------- | ------------- | -------------------------- |
| oid  | ObjectIdentifier | Y             | 包含应作为单个值获取的 OID |

- 返回值
  - varbind对象



### **multiwalk**

通过一次操作检索多个 OID“下方”的所有值。

注意：这将根据需要发出尽可能多的“GetNext”请求。

这几乎与`walk()`除了它能够同时迭代多个 OID 之外。

> **client.multiwalk(oids)**

- 参数

| 参数 | 类型                   | 是否必须(Y/N) | 说明                       |
| ---- | ---------------------- | ------------- | -------------------------- |
| oids | List(ObjectIdentifier) | Y             | 包含应作为单个值获取的 OID |



```python
from usr.snmp_api import Client, V2C, OctetString
from usr.snmp_api import ObjectIdentifier as OID    
client = Client("220.180.239.212", V2C("public"), port=9654)
rets = client.multiwalk(
    [OID('1.3.6.1.2.1.1'), OID('1.3.6.1.4.1.1')]
)

# rets 返回迭代器对象需要迭代
# 迭代返回varBind对象
# for ret in rets:
#	print(ret)
```



### **bulkwalk** 

与`walk()`但使用“批量”请求代替。

“批量”请求在一次请求中获取多个 OID，因此效率更高，但较大的返回值可能会溢出传输缓冲区。

> **client.bulkwalk(oids, bulk_size=10)**

| 参数      | 类型                   | 是否必须(Y/N) | 说明                       |
| --------- | ---------------------- | ------------- | -------------------------- |
| oids      | List(ObjectIdentifier) | Y             | 包含应作为单个值获取的 OID |
| bulk_size | int                    | N(默认10)     | 定义每个列表的最大长度     |

使用

```python
from usr.snmp_api import Client, V2C, OctetString
from usr.snmp_api import ObjectIdentifier as OID    

client = Client("220.180.239.212", V2C("public"), port=9654)
rets = client.bulkwalk([OID("1.3.6.1.2.1.2.2.1")])

# ret 返回迭代器对象需要迭代
# 迭代返回varBind对象
# for ret in rets:
#	print(ret)
```



### table

获取 SNMP 表

生成的输出将是一个字典列表，其中每个字典对应于表的一行。

SNMP 表的索引如下：

```
<base-oid>.<column-id>.<row-id>
```

“row-id”可以是单个数值，也可以是部分 OID。row-id 将包含在`'0'`每行的键中（作为字符串），代表该部分 OID（通常是可以在其他表中使用的后缀）。此密钥`'0'`由 自动注入 `qpysnmp`。这确保即使对于本身不包含该值的表，行索引也可用。

SNMP 表首先按列获取，然后按行获取（根据定义的 MIB 结构的性质）。这意味着此方法必须在能够返回任何内容之前使用完整的表

> **client.table(oid)**

- 参数

| 参数 | 类型             | 是否必须(Y/N) | 说明                       |
| ---- | ---------------- | ------------- | -------------------------- |
| oid  | ObjectIdentifier | Y             | 包含应作为单个值获取的 OID |

- 返回值
  - List对象

使用

```python
from usr.snmp_api import Client, V2C, OctetString
from usr.snmp_api import ObjectIdentifier as OID    

client = Client("220.180.239.212", V2C("public"), port=9654)
ret = client.table(OID("1.3.6.1.2.1.2.2.1"))
# ret = [{'0': '1', '1': Integer(1), ... '22': ObjectIdentifier('0.0')}]
```



### bulktable

与[`table()`]但使用“批量”请求相同。

“批量”请求在一次请求中获取多个 OID，因此效率更高，但较大的返回值可能会溢出传输缓冲区。

> **client.bulktable(oids, bulk_size=10)**

| 参数      | 类型                   | 是否必须(Y/N) | 说明                       |
| --------- | ---------------------- | ------------- | -------------------------- |
| oids      | List(ObjectIdentifier) | Y             | 包含应作为单个值获取的 OID |
| bulk_size | int                    | N(默认10)     | 定义每个列表的最大长度     |

- 返回值
  - 同table返回值



## X690Type

x690类型

主要包含

- TYPECLASS 类型

- TAG  标签
- NATURE 性质(非必须)

以Integer 0x02举例

拼包的时候会通过TAG, length和value去进行打包

`x690.types.Type`。请参阅 [`x690.types`](https://exhuma.github.io/x690/api/x690.html#module-x690.types)

**设置值**

> f = Integer(1)

**获取值**

> f.value()



### UnknownType

未知晓类型

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.CONSTRUCTED]**
>
>  **TAG = 0X99**



### Boolean

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE]**
>
> **TAG = 0X01**



### Null

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE]**
>
>  **TAG = 0X05**



### OctetString

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]**
>
>  **TAG = 0X04**



### Sequence

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.CONSTRUCTED]**
>
>  **TAG = 0X10**



### Integer

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE]**
>
>  **TAG = 0X02**



### ObjectIdentifier

>**TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
>**NATURE = [TypeNature.PRIMITIVE]**
>
> **TAG = 0X06**



### ObjectDescriptor

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]**
>
>  **TAG = 0X07**



### External

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.CONSTRUCTED]**
>
>  **TAG = 0X08**



### Real

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE]**
>
>  **TAG = 0X09**



### Enumerated

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE]**
>
>  **TAG = 0X0A**



### EmbeddedPdv

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.CONSTRUCTED]**
>
>  **TAG = 0X0B**



### Utf8String

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]**
>
>  **TAG = 0X0C**



### RelativeOid

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE]**
>
>  **TAG = 0X0D**



### Set

>**TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
>**NATURE = [TypeNature.CONSTRUCTED]**
>
> **TAG = 0X11**



### NumericString

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]**
>
>  **TAG = 0X12**



### PrintableString

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]**
>
>  **TAG = 0X13**



### T61String

>**TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
>**NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]**
>
> **TAG = 0X14**



### VideotexString

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]**
>
> **TAG = 0X15**



### IA5String

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]**
>
> **TAG = 0X16**



### UtcTime

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]**
>
> **TAG = 0X17**



### GeneralizedTime

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]**
>
> **TAG = 0X18**



### GraphicString

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]**
>
> **TAG = 0X19**



### VisibleString

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]**
>
> **TAG = 0X1A**



### GeneralString

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]**
>
> **TAG = 0X1B**



### UniversalString

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]**
>
>  **TAG = 0X1C**



### CharacterString

> **TAG = 0X1D**



### BmpString

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]**
>
> **TAG = 0X1E**



### EOC

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE]]**
>
> **TAG = 0X00**



### BitString

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]**
>
> **TAG = 0X03**



### Counter64

> **TYPECLASS: TypeClass = TypeClass.APPLICATION**
>
> **NATURE = [TypeNature.PRIMITIVE]**
>
> **TAG = 0X06**



### Counter

> **TYPECLASS: TypeClass = TypeClass.APPLICATION**
>
> **NATURE = [TypeNature.PRIMITIVE]**
>
> **TAG = 0X01**



### IpAddress

> **TYPECLASS: TypeClass = TypeClass.APPLICATION**
>
> **NATURE =[TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]**
>
> **TAG = 0X00**



### Gauge

> **TYPECLASS: TypeClass = TypeClass.APPLICATION**
>
> **NATURE = [TypeNature.PRIMITIVE]**
>
> **TAG = 0x02**



### TimeTicks

> **TYPECLASS: TypeClass = TypeClass.APPLICATION**
>
> **NATURE = [TypeNature.PRIMITIVE]**
>
> **TAG = 0x03**



### Opaque

> **TYPECLASS: TypeClass = TypeClass.APPLICATION**
>
> **NATURE =[TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]**
>
> **TAG = 0x04**



### NsapAddress

> **TYPECLASS: TypeClass = TypeClass.APPLICATION**
>
> **NATURE = [TypeNature.PRIMITIVE]**
>
> **TAG = 0x05**



### PDU

> **TYPECLASS: TypeClass = TypeClass.CONTEXT**
>
> **NATURE = [TypeNature.CONSTRUCTED]**
>
> **TAG = 0x00**



### NoSuchObject

> **TYPECLASS: TypeClass = TypeClass.CONTEXT**
>
> **NATURE = [TypeNature.PRIMITIVE]**
>
> **TAG = 0X00**



### NoSuchInstance

> **TYPECLASS: TypeClass = TypeClass.CONTEXT**
>
> **NATURE = [TypeNature.PRIMITIVE]**
>
> **TAG = 0X01**



### EndOfMibView

>**TYPECLASS: TypeClass = TypeClass.CONTEXT**
>
>**NATURE = [TypeNature.PRIMITIVE]**
>
>**TAG = 0X02**



### GetRequest

> **TYPECLASS: TypeClass = TypeClass.CONTEXT**
>
> **NATURE = [TypeNature.CONSTRUCTED]**
>
> **TAG = 0X00**



### GetResponse

> **TYPECLASS: TypeClass = TypeClass.CONTEXT**
>
> **NATURE = [TypeNature.CONSTRUCTED]**
>
> **TAG = 0X02**



### GetNextRequest

> **TYPECLASS: TypeClass = TypeClass.CONTEXT**
>
> **NATURE = [TypeNature.CONSTRUCTED]**
>
> **TAG = 0X01**



### SetRequest

> **TYPECLASS: TypeClass = TypeClass.CONTEXT**
>
> **NATURE = [TypeNature.CONSTRUCTED]**
>
> **TAG = 0X03**



### BulkGetRequest

> **TYPECLASS: TypeClass = TypeClass.CONTEXT**
>
> **NATURE = [TypeNature.CONSTRUCTED]**
>
> **TAG = 0X05**



### InformRequest

> **TYPECLASS: TypeClass = TypeClass.CONTEXT**
>
> **NATURE = [TypeNature.CONSTRUCTED]**
>
> **TAG = 0X06**



### Trap

> **TYPECLASS: TypeClass = TypeClass.CONTEXT**
>
> **NATURE = [TypeNature.CONSTRUCTED]**
>
> **TAG = 0X07**



### Report

> **TAG = 0X08**



## 异常

待补充