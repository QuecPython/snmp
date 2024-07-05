# QuecPython SNMP API Documentation

This module contains high-level functions for accessing the SNMP library.



## Common Structure Objects

### BulkResult

> br = **BulkResult(scalars, repeating_out)**

| Parameter     | Type                                  | Description                                 |
| ------------- | ------------------------------------- | ------------------------------------------- |
| scalars       | dict(X690.ObjectIdentifier=X690.Type) | Dictionary containing OID and value mapping |
| repeating_out | list(varbind)                         | List of varbind collections                 |

#### Get Scalars

```python
br.scalars
```



#### Get Repeating Out

> br.repeating_out



### VarBind

> vb = VarBind(oid, value)

| Parameter | Type                  | Description                  |
| --------- | --------------------- | ---------------------------- |
| oid       | X690.ObjectIdentifier | X690.ObjectIdentifier object |
| value     | x690.types            | x690.types object            |



#### Get OID

```python
oid = vb.oid
# Get the raw value
oid.value()
```



#### Get Value

```python
v = vb.value
# Get the raw value
v.value()
```



## Client

Type: `object`

Client to execute SNMP commands on remote devices.

To run SNMP commands on a remote device, create an instance for that device and call instance methods.

Credentials are instances obtained from the class used to determine the appropriate communication model for this client instance.

> **Client(ip, credentials, port=161, sender=udp_send, context_name=b"", engine_id=b"")**

- Parameters

| Parameter    | Type     | Required (Y/N)  | Description                                                  |
| ------------ | -------- | --------------- | ------------------------------------------------------------ |
| ip           | str      | Y               | IP address of the remote SNMP device                         |
| credentials  | V2C      | Y               | User credentials defining the underlying protocol in use     |
| port         | int      | N (default 161) | UDP port of the remote device                                |
| sender       | function | N               | Function to replace UDP implementation externally            |
| context_name | bytes    | N               | Optional context for SNMPv3 requests (V3 not supported yet)  |
| engine_id    | bytes    | N               | Optional engine ID for SNMPv3 requests. Helper function provided to generate a valid ID. |

Example usage:

```python
from usr.snmp_api import Client, V2C
from usr.snmp_api import ObjectIdentifier as OID

client = Client("220.180.239.212", V2C("public"), port=9654)
```



### V3

Version 3 provides encryption and authentication suites. Currently, encryption lacks algorithms but supports authentication, which needs to be specified during Client initialization, for example:

```python
from usr.snmp_common import Auth, Priv
from usr.snmp_api import Client, V2C, OctetString, V3
from usr.snmp_api import ObjectIdentifier as OID

# Authentication without encryption
client = Client("220.180.239.212", V3("ftt", auth=Auth(b'auth123456', "md5")), port=9654)
output = client.get("1.3.6.1.2.1.1.1.0")

# Encryption and authentication
client = Client("220.180.239.212", V3("ftt", auth=Auth(b'auth123456', "md5"), priv=Priv(b'priv123456', "aes")), port=9654)
output = client.get("1.3.6.1.2.1.1.1.0")
```

- V3 Parameters

| Parameter | Type | Description                                                  |
| --------- | ---- | ------------------------------------------------------------ |
| username  | str  | Username for testing, here using 'ftt'                       |
| auth      | Auth | Authentication Auth(key, crypt) <br> Key must be byte type<br> Cryptographic method must be string type, currently supports (md5, sha1) |
| priv      | Priv | Encryption Priv(key, crypt)<br> Key must be byte type for encryption<br> Cryptographic method must be string type, currently supports (aes, des) |



### get

Retrieves the value for a single OID.

> **client.get(oid)**

- Parameters

| Parameter | Type             | Required (Y/N) | Description                           |
| --------- | ---------------- | -------------- | ------------------------------------- |
| oid       | ObjectIdentifier | Y              | OID to be retrieved as a single value |



### multiget

Retrieves (scalar) values from multiple OIDs in one request.

> **client.multiget(oids)**

| Parameter | Type                   | Required (Y/N) | Description                           |
| --------- | ---------------------- | -------------- | ------------------------------------- |
| oids      | List(ObjectIdentifier) | Y              | OIDs to be retrieved as single values |

Example usage:

```python
from usr.snmp_api import ObjectIdentifier as OID

client = Client("127.0.0.1", V2C("private"), port=50009)
result = client.multiget(
    [OID('1.3.6.1.2.1.1.2.0'), OID('1.3.6.1.2.1.1.1.0')]
)
```



### **getnext**

Executes a single SNMP GETNEXT request (used in *walk*).

> **client.getnext(oid)**

- Parameters

| Parameter | Type             | Required (Y/N) | Description                    |
| --------- | ---------------- | -------------- | ------------------------------ |
| oid       | ObjectIdentifier | Y              | OID to get the next value from |

- Return Value
  - VarBind object



Usage

```python
client = Client("220.180.239.212", V2C("public"), port=9654)
# The line below needs to be "awaited" to get the result.
# This is not shown here to make it work with doctest
coro = client.client.getnext(OID('1.2.3.4'))
print(coro)
# coro= VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.1.1.0), value=OctetString(value = b'Linux localhost.localdomain 3.10.0-1127.el7.x86_64 #1 SMP Tue Mar 31 23:36:51 UTC 2020 x86_64'))
```



### multigetnext

Executes a single multi-oid GETNEXT request.

This request sends a packet to the remote host asking for the OID values following one or more specified OIDs.

> **client.multigetnext(oids)**

| Parameter | Type                   | Required (Y/N) | Description                      |
| --------- | ---------------------- | -------------- | -------------------------------- |
| oids      | List(ObjectIdentifier) | Y              | OIDs to get the next values from |

- Return Value
  - Collection of VarBind objects

Usage

```python
from usr.snmp_api import Client, V2C, OctetString
from usr.snmp_api import ObjectIdentifier as OID

client = Client("220.180.239.212", V2C("public"), port=9654)
ret = client.multigetnext([OID('1.3.6.1.2.1.1.2.0'), OID('1.3.6.1.2.1.1.1.0')])

# result = [VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.1.3.0), value=TimeTicks(value = 10932803)), VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.1.2.0), value=ObjectIdentifier(value = 1.3.6.1.4.1.8072.3.2.10))]
```



### bulkget

Performs a "bulk" get operation and returns a `BulkResult` instance. This includes a mapping of scalar variables ("non-repeaters") and a List instance containing the remaining list ("repeaters").

The list is ordered in the same way as the SNMP response (whatever the remote device returns).

This operation allows you to retrieve a single/scalar value *and a list of values ("repeating values")* in one request. For example, you can retrieve the hostname (a scalar value), a list of interfaces (a repeating value), and a list of physical entities (another repeating value) in one request.

Note that this is like a **getnext** request for scalar values! Thus, you will receive the values of OIDs that *immediately follow* the OIDs you specify for scalar values and repeating values!

> **client.bulkget(scalar_oids, repeating_oids, max_list_size=1)**

| Parameter      | Type                   | Required (Y/N) | Description                  |
| -------------- | ---------------------- | -------------- | ---------------------------- |
| scalar_oids    | list(ObjectIdentifier) | Y              | OIDs to get as single values |
| repeating_oids | list(ObjectIdentifier) | Y              | OIDs to get as lists         |
| max_list_size  | int                    | N (default 1)  | Maximum length of each list  |

Usage

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

Return Value Type

- BulkResult type



### set

Updates a value on the remote host

The value must be a subclass of `x690.types.Type`. See [`x690.types`](https://exhuma.github.io/x690/api/x690.html#module-x690.types) for a collection of predefined types.

> **client.set(oid, value)**

- Parameters

| Parameter | Type             | Required (Y/N) | Description                               |
| --------- | ---------------- | -------------- | ----------------------------------------- |
| oid       | ObjectIdentifier | Y              | OID containing the single value to be set |
| value     | X690Type         | Y              | Value type to be set                      |

- Return Value
  - Set value



### multiset

Performs an SNMP SET request for multiple OIDs. Results are returned as a plain Python data structure.

> **client.multiset(mappings)**

- Parameters

| Parameter | Type | Required (Y/N) | Description |
| --------- | ---- | -------------- | ----------- |
| mapping   | dict | Y              | {oid:value} |

Usage

```python
from usr.snmp_api import Client, V2C, OctetString
from usr.snmp_api import ObjectIdentifier as OID

client = Client("220.180.239.212", V2C("public"), port=9654)
coro = client.multiset({
    OID('1.3.6.1.2.1.1.4.0'): OctetString(b'new-contact'),
    OID('1.3.6.1.2.1.1.6.0'): OctetString(b'new-location')
})
# coro return value {ObjectIdentifier('1.3.6.1.2.1.1.4.0'): OctetString(b'contact'), OID('1.3.6.1.2.1.1.6.0'): OctetString(b'new-location')}
```



### walk

A convenience method for `multiwalk()` that delegates using just one OID.

> **client.walk(oid)**

- Parameters

| Parameter | Type             | Required (Y/N) | Description                      |
| --------- | ---------------- | -------------- | -------------------------------- |
| oid       | ObjectIdentifier | Y              | OID to retrieve all values below |

- Return Value
  - varbind object



### **multiwalk**

Retrieves all values "below" multiple OIDs in one operation.

Note: This will issue as many "GetNext" requests as necessary.

This is almost identical to `walk()` except that it can iterate multiple OIDs simultaneously.

> **client.multiwalk(oids)**

- Parameters

| Parameter | Type                   | Required (Y/N) | Description                       |
| --------- | ---------------------- | -------------- | --------------------------------- |
| oids      | List(ObjectIdentifier) | Y              | OIDs to retrieve all values below |

```python
from usr.snmp_api import Client, V2C, OctetString
from usr.snmp_api import ObjectIdentifier as OID
client = Client("220.180.239.212", V2C("public"), port=9654)
rets = client.multiwalk(
    [OID('1.3.6.1.2.1.1'), OID('1.3.6.1.4.1.1')]
)

# rets return iterator object needs to be iterated
# Iterating returns varBind object
# for ret in rets:
#   print(ret)
```



### **bulkwalk**

Similar to `walk()` but uses "bulk" requests instead.

"Bulk" requests fetch multiple OIDs in one request, thus being more efficient, but larger return values might overflow the transport buffer.

> **client.bulkwalk(oids, bulk_size=10)**

| Parameter | Type                   | Required (Y/N) | Description                             |
| --------- | ---------------------- | -------------- | --------------------------------------- |
| oids      | List(ObjectIdentifier) | Y              | OIDs to retrieve all values below       |
| bulk_size | int                    | N (default 10) | Defines the maximum length of each list |

Usage

```python
from usr.snmp_api import Client, V2C, OctetString
from usr.snmp_api import ObjectIdentifier as OID    

client = Client("220.180.239.212", V2C("public"), port=9654)
rets = client.bulkwalk([OID("1.3.6.1.2.1.2.2.1")])

# rets returns an iterator object that needs to be iterated
# Iterating returns varBind objects
# for ret in rets:
#   print(ret)
```



### table

Retrieves an SNMP table.

The output generated will be a list of dictionaries, each corresponding to a row in the table.

The indexing of an SNMP table is as follows:

```php
<base-oid>.<column-id>.<row-id>
```

The "row-id" can be a single number or a part OID. The row-id will be included in the key `'0'` in each row (as a string), representing that part of the OID (often a suffix that can be used in other tables). This key `'0'` is automatically injected by `qpysnmp`. This ensures that even for tables that do not contain the value itself, the row index is available.

SNMP tables are first retrieved by column and then by row (according to the nature of the defined MIB structure). This means that this method must use the complete table before it can return any content.

> **client.table(oid)**

- Parameters

| Parameter | Type             | Required (Y/N) | Description                                     |
| --------- | ---------------- | -------------- | ----------------------------------------------- |
| oid       | ObjectIdentifier | Y              | OID containing the single value to be retrieved |

- Return Value
  - List object

Usage

```python
from usr.snmp_api import Client, V2C, OctetString
from usr.snmp_api import ObjectIdentifier as OID    

client = Client("220.180.239.212", V2C("public"), port=9654)
ret = client.table(OID("1.3.6.1.2.1.2.2.1"))
# ret = [{'0': '1', '1': Integer(1), ... '22': ObjectIdentifier('0.0')}]
```



### bulktable

Similar to [`table()`] but uses "bulk" requests.

"Bulk" requests fetch multiple OIDs in one request, thus being more efficient, but larger return values might overflow the transport buffer.

> **client.bulktable(oids, bulk_size=10)**

| Parameter | Type                   | Required (Y/N) | Description                             |
| --------- | ---------------------- | -------------- | --------------------------------------- |
| oids      | List(ObjectIdentifier) | Y              | OIDs to retrieve all values below       |
| bulk_size | int                    | N (default 10) | Defines the maximum length of each list |

- Return Value
  - Similar to the return value of table



## X690Type

X690 types include:

- TYPECLASS: Type Class
- TAG: Tag
- NATURE: Nature (not mandatory)

Example using Integer 0x02:

When packaging, it uses TAG, length, and value to perform the packing.

`x690.types.Type`. For more details, see [`x690.types`](https://exhuma.github.io/x690/api/x690.html#module-x690.types)

**Setting a Value**

> f = Integer(1)

**Getting a Value**

> f.value()

### UnknownType

Unknown Type

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.CONSTRUCTED]**
>
> **TAG = 0X99**

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
> **TAG = 0X05**

### OctetString

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]**
>
> **TAG = 0X04**

### Sequence

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.CONSTRUCTED]**
>
> **TAG = 0X10**

### Integer

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE]**
>
> **TAG = 0X02**

### ObjectIdentifier

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE]**
>
> **TAG = 0X06**

### ObjectDescriptor

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]**
>
> **TAG = 0X07**

### External

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.CONSTRUCTED]**
>
> **TAG = 0X08**

### Real

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE]**
>
> **TAG = 0X09**

### Enumerated

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE]**
>
> **TAG = 0X0A**

### EmbeddedPdv

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.CONSTRUCTED]**
>
> **TAG = 0X0B**

### Utf8String

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]**
>
> **TAG = 0X0C**

### RelativeOid

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE]**
>
> **TAG = 0X0D**

### Set

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.CONSTRUCTED]**
>
> **TAG = 0X11**

### NumericString

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]**
>
> **TAG = 0X12**

### PrintableString

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]**
>
> **TAG = 0X13**

### T61String

> **TYPECLASS: TypeClass = TypeClass.UNIVERSAL**
>
> **NATURE = [TypeNature.PRIMITIVE, TypeNature.CONSTRUCTED]**
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
> **TAG = 0X1C**

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
> **NATURE = [TypeNature.PRIMITIVE]]
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

> **TYPECLASS: TypeClass = TypeClass.CONTEXT**
>
> **NATURE = [TypeNature.PRIMITIVE]**
>
> **TAG = 0X02**

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

## Exceptions

To be supplemented.