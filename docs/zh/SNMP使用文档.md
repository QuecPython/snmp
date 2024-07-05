# QuecPython SNMP 使用文档

### SNMP简介

- `snmp`(`Simple Network Management Protocol`，简单网络管理协议)，该协议的实现以及应用是采用`C/S`模型的特殊模式：代理/管理站模型。
- 代理是指提供`snmp`协议服务的网络设备，可以提供设备网络状态，配置信息，并且可以向管理站提供网络事件告警，响应来自网络的各种请求信息
- 管理站是类似于客户端角色，会向不同的代理请求获取数据返回
- 协议通过`UDP`端口161（代理端端口）和162（管理站`trap`进程开放端口）进行通信
- 代理会提供大量的对象标识符（`OID－Object Identifiers`），一个`OID`是一个唯一的键值对，每个`OID`都对应了不同的系统信息
- `OID`都非常长，使得人们难以记住，人们就设计了一种将数字`OID`翻译为人们可读的格式，翻译映射保存在“管理信息基础"（`Management Infomation Base`,`MIB`)的无格式文本文件里
- `snmp`有两种数据交互方式，请求和`trap`，请求是指管理站向代理设备发送`GET`请求，获取相应的网络信息，是主动形式的网络监控，`trap`是指配置代理让其监测到某个特殊事件的时候主动向管理站发送告警
- 有三个常用版本：`SNMPv1`、`SNMPv2c`、`SNMPv3`，其中`SNMPv1`和`SNMPv2c`被广泛应用，但是由于这些协议的不安全特性，通常只使用只读访问，`SNMPv3`是具有安全性的通信协议，`v1`和`v2c`采用相同的团体字认证参数（默认该参数是`public`，生产环境下需要进行修改），`v3`版本采用基于用户账号密码的方式进行认证

### SNMP服务搭建

文档演示使用Ubuntu18.04系统进行snmp服务的安装配置

#### 软件依赖

- `snmpd`：`snmp`服务端软件，提供开放端口用于提供给客户端请求的返回数据(系统状态信息等)
- `snmp`：`snmp`客户端软件，用于向服务端发送请求获取对方的系统状态信息
- `snmp-mibs-downloader`：用来下载更新本地`mib`库的软件

执行命令如下，该命令之后会安装上一系列`snmp`相关的工具，如`snmpwalk`, `net-snmp-create-v3-user`,`snmptranslate`等

```shell
$ sudo apt install snmp snmpd snmp-mibs-downloader libsnmp-dev
```

#### 基本配置与操作

查看`snmpd`状态

```shell
$ sudo systemctl status snmpd
```

配置管理`MIB`库

代理端更新`mib`库，更新到代理库的信息会可以查看`/var/lib/snmp/mibs`或者`/var/lib/mibs`

```shell
$ sudo download-mibs
```

开启`MIB`数据库的`OID`和可读字符串的转换，把最后一行`mibs`注释

```awk
$ sudo vim /etc/snmp/snmp.conf
mibs: 
修改为
# mibs:
```

查看`MIB`库的`OID`映射关系

```shell
$ snmptranslate -Tz                
"org"            "1.3"
"dod"            "1.3.6"
"internet"            "1.3.6.1"
"directory"            "1.3.6.1.1"
"mgmt"            "1.3.6.1.2"
"mib-2"            "1.3.6.1.2.1"
"system"            "1.3.6.1.2.1.1"
"sysDescr"            "1.3.6.1.2.1.1.1"
"sysObjectID"            "1.3.6.1.2.1.1.2"
"sysUpTime"            "1.3.6.1.2.1.1.3"
"sysUpTimeInstance"            "1.3.6.1.
...
```

当执行`snmp`采集程序的时候程序会查询固定位置的`MIB`文件，如果存在，则翻译，所以如果有自定义的`MIB`文件，直接放入到指定位置即可获取到翻译后的查询，默认`MIB`文件的位置如下

```shell
$ snmpwalk --help
  -M DIR[:...]          look in given list of directories for MIBs
    (default: $HOME/.snmp/mibs:/usr/share/snmp/mibs:/usr/share/snmp/mibs/iana:/usr/share/snmp/mibs
```

#### 测试基本的信息获取

##### snmp1和snmpv2c

`snmpwalk`是安装`snmp`服务时候附加安装的工具，可用于测试`snmp`服务的访问

`-v`参数是用于指定版本

`-c`参数指定团体字认证参数，由于默认是`public`，所以可以直接使用该参数

`localhost`是指定代理服务器的地址，由于现在代理和管理站安装在同一台机器，所以使用`localhost`作为代理的地址

`.1.3.6.1.2.1.1.1`表示的是`OID`的参数信息，该参数表示系统主机信息

下面两条命令的输出是一样的

```shell
$ snmpwalk -v 1 -c public localhost .1.3.6.1.2.1.1.1
$ snmpwalk -v 2c -c public localhost .1.3.6.1.2.1.1.1
SNMPv2-MIB::sysDescr.0 = STRING: Linux gong 5.15.0-48-generic #203-Ubuntu SMP Wed Aug 10 17:40:03 UTC 2022 x86_64
```

如果想获取更多信息，需要把`OID`的参数改短一些

比如改成`.1.3.6.1.2`，获取到的数据就更多了，`snmp`获取信息的时候是采用前缀匹配的形式，当指定的`OID`越短，匹配的信息也就越多

```shell
$ snmpwalk -v 1 -c public localhost .1.3.6.1.2      
SNMPv2-MIB::sysDescr.0 = STRING: Linux gong 5.15.0-48-generic #203-Ubuntu SMP Wed Aug 10 17:40:03 UTC 2022 x86_64
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (234221) 0:39:02.21
SNMPv2-MIB::sysContact.0 = STRING: Me <me@example.org>
SNMPv2-MIB::sysName.0 = STRING: gong
SNMPv2-MIB::sysLocation.0 = STRING: Sitting on the Dock of the Bay
SNMPv2-MIB::sysServices.0 = INTEGER: 72
SNMPv2-MIB::sysORLastChange.0 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORID.1 = OID: SNMP-FRAMEWORK-MIB::snmpFrameworkMIBCompliance
SNMPv2-MIB::sysORID.2 = OID: SNMP-MPD-MIB::snmpMPDCompliance
SNMPv2-MIB::sysORID.3 = OID: SNMP-USER-BASED-SM-MIB::usmMIBCompliance
SNMPv2-MIB::sysORID.4 = OID: SNMPv2-MIB::snmpMIB
SNMPv2-MIB::sysORID.5 = OID: SNMP-VIEW-BASED-ACM-MIB::vacmBasicGroup
SNMPv2-MIB::sysORID.6 = OID: TCP-MIB::tcpMIB
SNMPv2-MIB::sysORID.7 = OID: UDP-MIB::udpMIB
SNMPv2-MIB::sysORID.8 = OID: IP-MIB::ip
SNMPv2-MIB::sysORID.9 = OID: SNMP-NOTIFICATION-MIB::snmpNotifyFullCompliance
SNMPv2-MIB::sysORID.10 = OID: NOTIFICATION-LOG-MIB::notificationLogMIB
SNMPv2-MIB::sysORDescr.1 = STRING: The SNMP Management Architecture MIB.
SNMPv2-MIB::sysORDescr.2 = STRING: The MIB for Message Processing and Dispatching.
SNMPv2-MIB::sysORDescr.3 = STRING: The management information definitions for the SNMP User-based Security Model.
SNMPv2-MIB::sysORDescr.4 = STRING: The MIB module for SNMPv2 entities
SNMPv2-MIB::sysORDescr.5 = STRING: View-based Access Control Model for SNMP.
SNMPv2-MIB::sysORDescr.6 = STRING: The MIB module for managing TCP implementations
SNMPv2-MIB::sysORDescr.7 = STRING: The MIB module for managing UDP implementations
SNMPv2-MIB::sysORDescr.8 = STRING: The MIB module for managing IP and ICMP implementations
SNMPv2-MIB::sysORDescr.9 = STRING: The MIB modules for managing SNMP Notification, plus filtering.
SNMPv2-MIB::sysORDescr.10 = STRING: The MIB module for logging SNMP Notifications.
SNMPv2-MIB::sysORUpTime.1 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.2 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.3 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.4 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.5 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.6 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.7 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.8 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.9 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.10 = Timeticks: (0) 0:00:00.00
HOST-RESOURCES-MIB::hrSystemUptime.0 = Timeticks: (451727) 1:15:17.27
HOST-RESOURCES-MIB::hrSystemDate.0 = STRING: 2022-9-25,11:0:56.0,+8:0
HOST-RESOURCES-MIB::hrSystemInitialLoadDevice.0 = INTEGER: 393216
HOST-RESOURCES-MIB::hrSystemInitialLoadParameters.0 = STRING: "BOOT_IMAGE=/vmlinuz-5.15.0-48-generic root=UUID=ef5920a3-64eb-4d3f-b794-156d2d97cef9 ro quiet splash vt.handoff=7
"
HOST-RESOURCES-MIB::hrSystemNumUsers.0 = Gauge32: 2
HOST-RESOURCES-MIB::hrSystemProcesses.0 = Gauge32: 461
HOST-RESOURCES-MIB::hrSystemMaxProcesses.0 = INTEGER: 0
End of MIB
```

返回数据详解

主要格式是`SNMPv2-MIB::{OID[可读字符串]}.{细分点,从0开始} = {数据格式}: {数据信息}`

```apache
SNMPv2-MIB::sysDescr.0 = STRING: Linux gong 5.15.0-48-generic #203-Ubuntu SMP Wed Aug 10 17:40:03 UTC 2022 x86_64
```

##### snmp3

由于`v3`版本采用基于用户的认证方式，所以需要先创建一个测试用户用于认证

创建用户的过程当中需要停止`snmpd`服务

```shell
$ sudo systemctl stop snmpd
```

创建用户的命令格式如下，`net-snmp-create-v3-user`是安装软件时`libsnmp-dev`包提供的

```shell
$ net-snmp-create-v3-user [-ro] [-A authpass] [-X privpass] [-a MD5|SHA|SHA-512|SHA-384|SHA-256|SHA-224] [-x DES|AES] [username]
```

`-ro`参数表示该用户只读

`-A`指定用户密码短语，至少为8个字符，用于生成身份验证密钥

`-X`至少为8字符，用于生成加密密钥

`-a`指定用户身份验证类型，该指定会使用不同的算法进行运算

`-x`指定加密验证类型

创建一个用户如下, 采用认证参数`authtest`，认证加密算法采用`SHA`，加密参数`privtest`，加密算法采用`AES`，指定用户名称`gong`

```shell
$ sudo net-snmp-create-v3-user -ro -A authtest -a MD5 -X privtest -x AES quectel
adding the following line to /var/lib/snmp/snmpd.conf:
   createUser quectel MD5 "authtest" AES "privtest"
adding the following line to /usr/share/snmp/snmpd.conf:
   rouser quectel
```

依据提示的信息去查看对应修改的文件

```shell
$ cat /var/lib/snmp/snmpd.conf
#发现最后一行是刚刚填写的认证信息
...
createUser quectel MD5 "authtest" AES "privtest"
$ cat /usr/share/snmp/snmpd.conf
# 最后一行是如下
rouser quectel
```

重启服务并且进行验证

参数中指定版本，用户名称，认证算法`MD5`，认证参数`authtest`，加密算法`AES`，加密参数`privtest`

```
-l`指定安全级别，可选参数有`noAuthNoPriv`,`authNoPriv`,`authPriv`，由于创建的用户同时指定了认证和加密，所以现在该参数填写`authPriv
```

由于`MIB`库的存在，`OID`参数也可以传递可读字符串

```shell
$ sudo systemctl restart snmpd
$ snmpwalk -v 3 -u quectel -a MD5 -A authtest -x AES -X privtest -l authPriv localhost sysDescr
```

#### 访问信息范围控制

有些时候我们需要获取一些信息，但是执行命令的时候发现获取不到，但是知道应该是有这个信息的

比如现在需要获取网卡信息

执行命令如下，网卡信息对应的`OID`是`.1.3.6.1.2.1.31.1.1.1.1`或者`ifName`

```shell
$ snmpwalk -v 2c -c public localhost .1.3.6.1.2.1.31.1.1.1.1
IF-MIB::ifName = No more variables left in this MIB View (It is past the end of the MIB tree)
```

主要是配置文件当中限制了代理可以返回的信息，修改`/etc/snmp/snmpd.conf`

```apache
#找到下面两行配置注释掉
view   systemonly  included   .1.3.6.1.2.1.1
view   systemonly  included   .1.3.6.1.2.1.25.1

# 添加一行，不要开放太多信息，需要实际按需开放
view   systemonly  included   .1.3.6.1.2.1.31.1.1.1.1

# 或者图省事也可以只添加一行，这样就开放了所以信息了，生产环境需要慎重
view   systemonly  included   .1
```

重启服务

```shell
$ sudo systemctl restart snmpd
```

执行命令，查看输出，发现获取数据成功

```shell
$ snmpwalk -v 2c -c public localhost .1.3.6.1.2.1.31.1.1.1.1
IF-MIB::ifName.1 = STRING: lo
IF-MIB::ifName.2 = STRING: enp3s0
IF-MIB::ifName.3 = STRING: wlp4s0
```

#### snmp1, snmp2c配置共同体认证参数

修改`/etc/snmp/snmpd.conf`，其中默认的认证参数是`public`，这个参数由于是默认的，公开的，不安全，所以需要修改为别的参数

```axapta
# 修改以下
rocommunity  public default -V systemonly
rocommunity6 public default -V systemonly
# 变成
rocommunity  changed default -V systemonly
rocommunity6 changed default -V systemonly
```

重启服务

```shell
$ sudo systemctl restart snmpd
```

测试使用 `public`认证参数，发现无响应

```shell
$ snmpwalk -v 2c -c public localhost .1.3.6.1.4.1.2021
Timeout: No Response from localhost
```

测试使用 `changed`参数，可以正常使用

```shell
$ snmpwalk -v 2c -c changed localhost sysDesc
SNMPv2-MIB::sysDescr.0 = STRING: Linux quectel 5.15.0-48-generic #203-Ubuntu SMP Wed Aug 10 17:40:03 UTC 2022 x86_64
```

#### 开放服务远程访问

查看端口开放，发现只能本地访问

```shell
$ sudo netstat -anp |grep 161
udp        0      0 127.0.0.1:161           0.0.0.0:*                           210652/snmpd        
udp6       0      0 ::1:161                 :::*                                210652/snmpd   
```

修改`/etc/snmp/snmpd.conf`

```apache
# 注释
agentaddress  127.0.0.1,[::1]
# 修改
agentAddress udp:161,udp6:[::1]:161
```

重启服务后查看端口

```shell
$ sudo netstat -antup |grep 161
udp        0      0 0.0.0.0:161             0.0.0.0:*           106387/snmpd        
udp6       0      0 ::1:161                 :::*                106387/snmpd 
```

### 模组客户端调试

[下载snmp代码](.././code)并上传至模组内

![image-20240705095053302](../media/image-20240705095053302.png)

SNMP V2

```python
>>> from usr.snmp_api import Client, V2C # 导入库文件
>>> 
>>> client = Client("0.0.0.0", V2C("public"), port=161)  # 创建实例
>>> client.get("1.3.6.1.2.1.1.1.0")  # 指令请求
GetResponse(1720144440, [VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.1.1.0), value=OctetString(value = b'Linux iZuf642p5ypuu6vbfpzae7Z 4.15.0-192-generic #203-Ubuntu SMP Wed Aug 10 17:40:03 UTC 2022 x86_64'))])
>>> 
```

SNMP V3

V3版本提供客户端加密和认证套件,  目前加密缺少算法支持（迭代中）, 仅支持认证, 认证需要在Client初始化的时候指定

```python
>>> from usr.snmp_common import Auth
>>> from usr.snmp_api import Client, V3
>>> 
>>> client = Client("0.0.0.0", V3("quectel", auth=Auth(b'authtest', "md5")), port=161)
>>> client.get("1.3.6.1.2.1.1.1.0")
GetResponse(1720144800, [VarBind(oid=ObjectIdentifier(value = 1.3.6.1.2.1.1.1.0), value=OctetString(value = b'Linux iZuf642p5ypuu6vbfpzae7Z 4.15.0-192-generic #203-Ubuntu SMP Wed Aug 10 17:40:03 UTC 2022 x86_64'))])
>>> 
```

更多指令示例代码查阅[API说明文档](./API说明文档.md)。