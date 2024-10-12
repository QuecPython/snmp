# QuecPython SNMP 代理端API说明文档

## API 说明

### SNMPAgent

> 该模块包含代理端Get、Set、Trap等服务，使用前需要创建一个SNMPAgent实例。

**示例：**

```python
from usr.snmp_agent import SNMPAgent
import dataCall
host = dataCall.getInfo(1, 0)[2][2]
post = 161
agent = SNMPAgent(host, post)
```

**参数：**

|参数|类型|说明|
|:---|---|---|
|host|str|当前网络IP，例如'10.221.171.193'|
|post|int|网络端口，例如161|

#### SNMPAgent.serve_forever

> 启动代理端服务。

**示例：**

```python
agent.serve_forever()
```

#### SNMPAgent.send_trap

> 代理端主动发送Trap消息。

**示例：**

```python
trap_oid = '1.3.6.1.4.1.9999.1.6.0'
trap_value = b'Trap Event Triggered'
trap_ip='192.168.1.100'
agent.send_trap(trap_oid, trap_value, trap_ip)
```

**参数：**

| 参数 | 类型  | 说明           |
| :--- | ----- | -------------- |
| trap_oid  | str   | Trap消息的OID |
| trap_value | str | Trap消息的值 |
| trap_ip | str | 接收Trap消息的IP地址 |
