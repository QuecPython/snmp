# QuecPython SNMP Agent API Documentation

## API Description

### SNMPAgent

> This module includes agent services such as Get, Set, Trap, etc. Before use, a SNMP Agent instance needs to be created.

**Example:**

```python
from usr.snmp_agent import SNMPAgent
import dataCall
host = dataCall.getInfo(1, 0)[2][2]
post = 161
agent = SNMPAgent(host, post)
```

**Parameters:**

|Parameter|Type|Explain|
|:---|---|---|
|host|str|Current network IP, such as '10.221.171.193'|
|post|int|Network port, such as 161|

#### SNMPAgent.serve_forever

> Start the agent service.

**Example:**

```python
agent.serve_forever()
```

#### SNMPAgent.send_trap

> The agent actively sends Trap messages.

**Example:**

```python
trap_oid = '1.3.6.1.4.1.9999.1.6.0'
trap_value = b'Trap Event Triggered'
trap_ip='192.168.1.100'
agent.send_trap(trap_oid, trap_value, trap_ip)
```

**Parameters:**

| Parameter | Type  | Explain           |
| :--- | ----- | -------------- |
| trap_oid  | str   | OID of Trap message |
| trap_value | str | The value of the Trap message |
| trap_ip | str | IP address for receiving Trap messages |
