import usocket as socket
import ustruct as struct
import _thread
import utime
import checkNet
import dataCall
from usr.queryfunction import QueryFunction
import modem

DEBUG_parse_snmpv2_packet = False
DEBUG_parse_snmpv3_packet = False

AuthoritativeEngineID = modem.getDevImei()
fun = QueryFunction()

class SNMPAgent:
    def __init__(self, host='0.0.0.0', port=161):
        self.host = host
        self.port = port
        self.oid_values = {
            '1.3.6.1.4.1.9999.1.1.7': 'Reboot',
            '1.3.6.1.4.1.9999.1.2.0': 'keepAliveDuration',
            '1.3.6.1.4.1.9999.1.3.2': 'Operator',
            '1.3.6.1.4.1.9999.1.4.0': 'APN',
            '1.3.6.1.4.1.9999.1.5.0': 'pwshute_en',
        }
        self.engine_id = AuthoritativeEngineID
        self.username = 'public'
        self.engine_boots = 1
        self.engine_time = 0
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))

    def encode_oid(self, oid):
        oid_parts = [int(i) for i in oid.split('.')]
        oid_encoded = struct.pack('!B', oid_parts[0] * 40 + oid_parts[1])  # OID前两个值的特殊编码规则
        for part in oid_parts[2:]:
            if part < 128:
                oid_encoded += struct.pack('!B', part)
            else:
                oid_encoded += struct.pack('!BB', (part >> 7) | 0x80, part & 0x7F)
        return oid_encoded

    def decode_oid(self, encoded_oid):
        oid_parts = [encoded_oid[0] // 40, encoded_oid[0] % 40]
        i = 1
        while i < len(encoded_oid):
            part = encoded_oid[i]
            if part < 128:
                oid_parts.append(part)
                i += 1
            else:
                part = (part & 0x7F) << 7 | encoded_oid[i + 1]
                oid_parts.append(part)
                i += 2
        return '.'.join(map(str, oid_parts))

    # Trap 消息发送函数
    def send_trap(self, trap_oid, value, trap_ip='192.168.1.100', trap_port=162): 
        new_value = b''
        if(value != None):
            new_value = value
        trap = b'\x30'  # SEQUENCE
        oid_encoded = b''
        if(trap_oid != None):
            oid_encoded = self.encode_oid(trap_oid)
        value_length = len(new_value)
        # message_id = 
        # message_id = b''
        # if(request_id != None):
        message_id = struct.pack('!I', int(utime.time()))
        max_msg_size = 65536
        max_message_size = b''
        if(max_msg_size != None):   
            max_message_size = struct.pack('!BBB', max_msg_size)
        user_name = b''
        if(self.username != None):   
            user_name = self.username
        contextEngineID = b''
        if(self.engine_id != None):     
            contextEngineID = self.engine_id
        # request_id = b''
        # if(request_id != None):     
        #     request_id = struct.pack('!I', request_id)
        request_id = struct.pack('!I', int(utime.time()))
        # SNMPv3 Header
        total_length = 57 + len(message_id) + len(max_message_size) + len(user_name) + len(AuthoritativeEngineID) + len(contextEngineID) + len(request_id) + len(oid_encoded) + value_length  # 动态计算总长度
        total_length = self.encode_ber_length(total_length)
        trap += total_length #struct.pack('!B', total_length)  # Total length
        trap += b'\x02\x01\x03'  # SNMP version 3
        trap += b'\x30' + struct.pack('!B', 10 + len(message_id) + len(max_message_size)) # global data
        trap += b'\x02' + struct.pack('!B', len(message_id)) + message_id # Message ID
        trap += b'\x02' + struct.pack('!B', len(max_message_size)) + max_message_size
        trap += b'\x04\x01\x00'
        trap += b'\x02\x01\x03'
        
        trap += b'\x04' + struct.pack('!B', 16 + len(AuthoritativeEngineID) + len(user_name)) 
        trap += b'\x30' + struct.pack('!B', 14 + len(AuthoritativeEngineID) + len(user_name)) 
        trap += b'\x04' + struct.pack('!B', len(AuthoritativeEngineID)) + AuthoritativeEngineID
        trap += b'\x02\x01\x00'
        trap += b'\x02\x01\x00'  
        trap += b'\x04' + struct.pack('!B', len(user_name)) + user_name    
        trap += b'\x04\x00'
        trap += b'\x04\x00'

        # ScopedPDU
        trap += b'\x30' + struct.pack('!B', 22 + len(contextEngineID) + len(request_id) + len(oid_encoded) + value_length)  # ScopedPDU length
        trap += b'\x04' + struct.pack('!B', len(contextEngineID)) + contextEngineID # contextEngineID (empty)
        trap += b'\x04\x00'  # contextName (empty)
        trap += b'\xA7' + struct.pack('!B', 16 + len(request_id) + len(oid_encoded) + value_length)  # PDU Type: trap

        trap += b'\x02\x04' + request_id  # 请求ID
        trap += b'\x02\x01\x00'  # error-status (no error)
        trap += b'\x02\x01\x00'  # error-index

        # Varbind
        trap += b'\x30' + struct.pack('!B', 6 + len(oid_encoded) + value_length)
        trap += b'\x30' + struct.pack('!B', 4 + len(oid_encoded) + value_length)

        # OID
        trap += b'\x06' + struct.pack('!B', len(oid_encoded)) + oid_encoded

        # Value
        trap += b'\x04' + struct.pack('!B', value_length) + new_value  # OctetString 类型

        # 通过 UDP socket 发送 Trap
        trap_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        trap_socket.sendto(trap, (trap_ip, trap_port))
        # print("[snmp_agent_v3][send_trap]trap:")
        # print(trap)
        # print("[snmp_agent_v3][send_trap]trap hex:")
        # for i in range(len(trap)):
        #     print("{:02x}".format(trap[i]), end=' ')
        print("SNMPv3 Trap sent to {}:{}".format(trap_ip, trap_port))
        trap_socket.close()

    # 示例触发 Trap 发送的功能
    def trigger_trap_event(self):
        trap_oid = '1.3.6.1.4.1.9999.1.6.0'  # 示例 Trap OID
        value = b'Trap Event Triggered'
        self.send_trap(trap_oid, value, trap_ip='192.168.1.100')

    def handle_get_request(self, *args):
        version = args[0]
        if(version == 1):
            oid = args[4]
            value = None
            if oid in self.oid_values:
                # value = self.oid_values[oid]
                readresult, objresult, value = fun.read(self.oid_values[oid])
                print("oid_values:", self.oid_values[oid], "readresult:", readresult, "objresult:", objresult, "value:", value)
            return self.build_snmpv2_response(value, args)
        elif(version == 3):
            oid = args[17]
            value = None
            if oid in self.oid_values:
                # value = self.oid_values[oid]
                readresult, objresult, value = fun.read(self.oid_values[oid])
                print("oid_values:", self.oid_values[oid], "readresult:", readresult, "objresult:", objresult, "value:", value)
            return self.build_snmpv3_response(value, args)
        return None            

    def handle_set_request(self, *args):
        version = args[0]
        if(version == 1):
            oid = args[4]
            value = None
            new_value = args[5]
            if oid in self.oid_values:
                # value = self.oid_values[oid]
                readresult, objresult, value = fun.write(self.oid_values[oid], [new_value.decode()])
                print("oid_values:", self.oid_values[oid], "readresult:", readresult, "objresult:", objresult, "value:", value)
            return self.build_snmpv2_response(new_value, args)
        elif(version == 3):
            oid = args[17]
            value = None
            new_value = args[18]
            if oid in self.oid_values:
                # value = self.oid_values[oid]
                readresult, objresult, value = fun.write(self.oid_values[oid], [new_value.decode()])
                print("oid_values:", self.oid_values[oid], "readresult:", readresult, "objresult:", objresult, "value:", value)
            return self.build_snmpv3_response(new_value, args)
        return None

    def encode_ber_length(self, length):
        """
        将给定的长度编码为 BER 格式。
        
        :param length: 整数，表示报文的实际长度
        :return: 字节串，表示 BER 编码后的长度字段
        """
        if length < 128:
            # 如果长度小于 128，则直接用一个字节表示
            return struct.pack('!B', length)
        else:
            # 否则，使用多字节表示，最高位设置为 1 表示长形式编码
            length_bytes = []
            while length > 0:
                length_bytes.append(length & 0xFF)
                length >>= 8
            # 反转列表以得到正确的顺序，并在最前面加上长度指示
            length_bytes.reverse()
            # 添加长度标识符（长度字节数量）
            length_bytes.insert(0, len(length_bytes) | 0x80)
            return bytes(length_bytes)

    def build_snmpv2_response(self, value, *args):
        new_value = b''
        if(value != None):
            new_value = value
        data = args[0]
        version = data[0]
        community = data[1]
        request_id = b''
        if(data[3] != None):     
            request_id = struct.pack('!I', data[3])
        oid = data[4]
        pdu_type=0xA2
        response = b'\x30'  # 序列
        oid_encoded = self.encode_oid(oid)
        value_length = len(new_value)

        # 总长度（动态计算）
        total_length = 29 + len(oid_encoded) + value_length

        response += struct.pack('!B', total_length)  # 整体长度
        response += b'\x02\x01' + struct.pack('!B', version)  # SNMP版本
        response += b'\x04' + struct.pack('!B', len(community)) + community.encode()  # 社区字符串
        response += struct.pack('!B', pdu_type)  # PDU类型 (GetResponse)
        response += struct.pack('!B', total_length - 9)  # PDU总长度

        response += b'\x02\x04' + request_id  # 请求ID
        response += b'\x02\x01\x00'  # 错误状态
        response += b'\x02\x01\x00'  # 错误索引

        # 变量绑定 (VarBind)
        response += b'\x30' + struct.pack('!B', 6 + len(oid_encoded) + value_length)
        response += b'\x30' + struct.pack('!B', 4 + len(oid_encoded) + value_length)

        # OID
        response += b'\x06' + struct.pack('!B', len(oid_encoded)) + oid_encoded

        # 值
        response += b'\x04' + struct.pack('!B', value_length) + new_value  # OctetString 类型

        return response

    def build_snmpv3_response(self, value, *args):
        """构建SNMP v3响应"""
        # print("[build_snmpv3_response]", args)
        new_value = b''
        if(value != None):
            new_value = value
        data = args[0]
        response = b'\x30'  # SEQUENCE
        oid_encoded = b''
        if(data[17] != None):
            oid_encoded = self.encode_oid(data[17])
        value_length = len(new_value)
        print("new_value:", new_value, "value_length:", value_length)
        message_id = b''
        if(data[1] != None):
            message_id = struct.pack('!I', data[1])
        max_message_size = b''
        if(data[2] != None):   
            max_message_size = struct.pack('!BBB', data[2])
        user_name = b''
        if(data[8] != None):   
            user_name = data[8]
            # user_name = b'auth'
        contextEngineID = b''
        if(data[11] != None):     
            contextEngineID = data[11]
        request_id = b''
        if(data[14] != None):     
            request_id = struct.pack('!I', data[14])
        # SNMPv3 Header
        total_length = 57 + len(message_id) + len(max_message_size) + len(user_name) + len(AuthoritativeEngineID) + len(contextEngineID) + len(request_id) + len(oid_encoded) + value_length  # 动态计算总长度
        total_length = self.encode_ber_length(total_length)
        response += total_length #struct.pack('!B', total_length)  # Total length
        response += b'\x02\x01\x03'  # SNMP version 3
        response += b'\x30' + struct.pack('!B', 10 + len(message_id) + len(max_message_size)) # global data
        response += b'\x02' + struct.pack('!B', len(message_id)) + message_id # Message ID
        response += b'\x02' + struct.pack('!B', len(max_message_size)) + max_message_size
        response += b'\x04\x01\x00'
        response += b'\x02\x01\x03'
        
        response += b'\x04' + struct.pack('!B', 16 + len(AuthoritativeEngineID) + len(user_name)) 
        response += b'\x30' + struct.pack('!B', 14 + len(AuthoritativeEngineID) + len(user_name)) 
        response += b'\x04' + struct.pack('!B', len(AuthoritativeEngineID)) + AuthoritativeEngineID
        response += b'\x02\x01\x00'
        response += b'\x02\x01\x00'  
        response += b'\x04' + struct.pack('!B', len(user_name)) + user_name    
        response += b'\x04\x00'
        response += b'\x04\x00'

        # ScopedPDU
        response += b'\x30' + struct.pack('!B', 22 + len(contextEngineID) + len(request_id) + len(oid_encoded) + value_length)  # ScopedPDU length
        response += b'\x04' + struct.pack('!B', len(contextEngineID)) + contextEngineID # contextEngineID (empty)
        response += b'\x04\x00'  # contextName (empty)
        response += b'\xA2' + struct.pack('!B', 16 + len(request_id) + len(oid_encoded) + value_length)  # PDU Type: GetResponse

        response += b'\x02\x04' + request_id  # 请求ID
        response += b'\x02\x01\x00'  # error-status (no error)
        response += b'\x02\x01\x00'  # error-index

        # Varbind
        response += b'\x30' + struct.pack('!B', 6 + len(oid_encoded) + value_length)
        response += b'\x30' + struct.pack('!B', 4 + len(oid_encoded) + value_length)

        # OID
        response += b'\x06' + struct.pack('!B', len(oid_encoded)) + oid_encoded

        # Value
        response += b'\x04' + struct.pack('!B', value_length) + new_value  # OctetString 类型

        return response

    def to_four_bytes(self, value):
        """ Convert a value to a four-byte"""
        if(len(value) < 4):
            return b'\x00' * (4 - len(value)) + value
        else:
            return value

    def parse_length_field(self, message, index):
        """ Parse the BER length field and return the length and the new index """
        if(len(message) < index):  # If the message is too short, return None
            return None, index
        length = message[index]
        index += 1
        if length & 0x80:  # If the high bit is set, it means the length is in multiple bytes
            num_bytes = length & 0x7F  # The number of length bytes
            message_tuples = message[index:index + num_bytes]
            length = struct.unpack('!I', self.to_four_bytes(message_tuples))
            message_len = length[0]
            length = message_len
            index += num_bytes
        return length, index

    def parse_integer(self, message, index):
        """ Parse an INTEGER from the message and return its value and new index """
        if(len(message) < index):  # If the message is too short, return None
            return None, index
        if message[index] != 0x02:  # INTEGER tag is 0x02
            if DEBUG_parse_snmpv3_packet: print("[parse_snmpv3_packet][parse_integer]Expected INTEGER, got", message[index])
            return None, index
        index += 1
        int_length, index = self.parse_length_field(message, index)
        if((int_length == None) or (int_length == 0)):  # If the length is 0, return None
            return None, index
        message_tuples = message[index:index + int_length]
        unpack_tuples = struct.unpack('!I', self.to_four_bytes(message_tuples))
        value = unpack_tuples[0]
        index += int_length
        return value, index

    def parse_octet_string(self, message, index):
        """ Parse an OCTET STRING from the message and return its value and new index """
        if(len(message) < index):  # If the message is too short, return None
            return None, index
        if message[index] != 0x04:  # OCTET STRING tag is 0x04
            if DEBUG_parse_snmpv3_packet: print("[parse_snmpv3_packet][parse_octet_string]Expected OCTET STRING, got", message[index])
            return None, index
        index += 1
        str_length, index = self.parse_length_field(message, index)
        if((str_length == None) or (str_length == 0)):  # If the length is 0, return None
            return None, index
        value = message[index:index + str_length]
        index += str_length
        return value, index

    def parse_sequence(self, message, index):
        """ Parse a SEQUENCE and return the length and new index """
        if(len(message) < index):  # If the message is too short, return None
            return None, index
        if message[index] != 0x30:  # SEQUENCE tag is 0x30
            if DEBUG_parse_snmpv3_packet: print("[parse_snmpv3_packet][parse_sequence]Expected SEQUENCE, got", message[index])
            return None, index
        index += 1
        seq_length, index = self.parse_length_field(message, index)
        return seq_length, index
    
    def parse_oid(self, message, index):
        """ Parse an OID from the message and return its value and new index """
        if message[index] != 0x06:  # OID tag is 0x06
            if DEBUG_parse_snmpv3_packet: print("[parse_snmpv3_packet][parse_oid]Expected OID, got", message[index])
            return None, index
        index += 1
        oid_length, index = self.parse_length_field(message, index)
        if((oid_length == None) or (oid_length == 0)):  # If the length is 0, return None
            return None, index
        value = self.decode_oid(message[index:index + oid_length])
        index += oid_length
        return value, index
    def parse_snmpv2_packet(self, data):
        index = 0
        if DEBUG_parse_snmpv2_packet: print("[parse_snmpv2_packet]Message: ", data, "Length:", len(data))
        # Parse the SNMPv2 message header
        # SEQUENCE (0x30)
        length, index = self.parse_sequence(data, index)
        if DEBUG_parse_snmpv2_packet:print("[parse_snmpv2_packet]Total Length:", length, "Current Index:", index)
        # SNMP Version (INTEGER 0x02)
        version, index = self.parse_integer(data, index)
        if DEBUG_parse_snmpv2_packet: print("[parse_snmpv2_packet]SNMP Version:", version, "Current Index:", index)
        # Community (OCTET STRING 0x04)
        community, index = self.parse_octet_string(data, index)
        if DEBUG_parse_snmpv2_packet: print("[parse_snmpv2_packet]community:", community, "Current Index:", index)

        # Now expecting GetRequest PDU
        # Pdu Type
        pdu_type = data[index]
        if DEBUG_parse_snmpv2_packet: print("[parse_snmpv2_packet]Pdu Type:", pdu_type, "Current Index:", index)
        # Request ID (INTEGER 0x02)
        index += 2
        request_id, index = self.parse_integer(data, index)
        if DEBUG_parse_snmpv2_packet: print("[parse_snmpv2_packet]Request ID:", request_id, "Current Index:", index)
        # Error Status (INTEGER 0x02)
        error_status, index = self.parse_integer(data, index)
        if DEBUG_parse_snmpv2_packet: print("[parse_snmpv2_packet]Error Status:", error_status, "Current Index:", index)
        # Error Index (INTEGER 0x02)
        error_index, index = self.parse_integer(data, index)
        if DEBUG_parse_snmpv2_packet: print("[parse_snmpv2_packet]Error Index:", error_index, "Current Index:", index)
        
        # Parse the Variable Bindings SEQUENCE
        # SEQUENCE (0x30)
        length, index = self.parse_sequence(data, index)
        oid = None
        value = None
        if(length != 0):
            # SEQUENCE (0x30)
            length, index = self.parse_sequence(data, index)
            if DEBUG_parse_snmpv2_packet: print("[parse_snmpv2_packet]Variable Bindings Length:", length, "Current Index:", index)
            # OID (0x06)
            oid, index = self.parse_oid(data, index)
            # Value (OCTET STRING 0x04)
            value, index = self.parse_octet_string(data, index)
        if DEBUG_parse_snmpv2_packet: print("[parse_snmpv2_packet]OID:", oid, "Value:", value, "Current Index:", index)
        return [version, community, pdu_type, request_id, oid, value]

    def parse_snmpv3_packet(self, data):
        index = 0
        if DEBUG_parse_snmpv3_packet: print("[parse_snmpv3_packet]Message: ", data, "Length:", len(data))
        # Parse the SNMPv3 message header
        # SEQUENCE (0x30)
        length, index = self.parse_sequence(data, index)
        if DEBUG_parse_snmpv3_packet:print("[parse_snmpv3_packet]Total Length:", length, "Current Index:", index)
        # SNMP Version (INTEGER 0x02)
        version, index = self.parse_integer(data, index)
        if DEBUG_parse_snmpv3_packet: print("[parse_snmpv3_packet]SNMP Version:", version, "Current Index:", index)
        # SEQUENCE (Message ID, Max Message Size, Message Flags, Security Model)
        length, index = self.parse_sequence(data, index)
        if DEBUG_parse_snmpv3_packet: print("[parse_snmpv3_packet]Message Length:", length, "Current Index:", index)
        # Message ID (INTEGER 0x02)
        message_id, index = self.parse_integer(data, index)
        if DEBUG_parse_snmpv3_packet: print("[parse_snmpv3_packet]Message ID:", message_id, "Current Index:", index)
        # Max Message Size (INTEGER 0x02)
        max_msg_size, index = self.parse_integer(data, index)
        if DEBUG_parse_snmpv3_packet: print("[parse_snmpv3_packet]Max Message Size:", max_msg_size, "Current Index:", index)
        # Message Flags (OCTET STRING 0x04)
        flags, index = self.parse_octet_string(data, index)
        if DEBUG_parse_snmpv3_packet: print("[parse_snmpv3_packet]Message Flags:", flags, "Current Index:", index)
        # Security Model (INTEGER 0x02)
        security_model, index = self.parse_integer(data, index)
        if DEBUG_parse_snmpv3_packet: print("[parse_snmpv3_packet]Security Model:", security_model, "Current Index:", index)
        # Authoritative Engine ID (OCTET STRING 0x04)
        index += 4 # Skip security params len and sequence len
        authoritative_engine_id, index = self.parse_octet_string(data, index)
        if DEBUG_parse_snmpv3_packet: print("[parse_snmpv3_packet]Authoritative Engine ID:", authoritative_engine_id, "Current Index:", index)
        # Authoritative Engine Boots (INTEGER 0x02)
        authoritative_engine_boots, index = self.parse_integer(data, index)
        if DEBUG_parse_snmpv3_packet: print("[parse_snmpv3_packet]Authoritative Engine Boots:", authoritative_engine_boots, "Current Index:", index)
        # Authoritative Engine Time (INTEGER 0x02)
        authoritative_engine_time, index = self.parse_integer(data, index)
        if DEBUG_parse_snmpv3_packet: print("[parse_snmpv3_packet]Authoritative Engine Time:", authoritative_engine_time, "Current Index:", index)
        # Username (OCTET STRING 0x04)
        username, index = self.parse_octet_string(data, index)
        if DEBUG_parse_snmpv3_packet: print("[parse_snmpv3_packet]Username:", username, "Current Index:", index)
        # Authentication Parameters (OCTET STRING 0x04)
        authentication_parameters, index = self.parse_octet_string(data, index)
        if DEBUG_parse_snmpv3_packet: print("[parse_snmpv3_packet]Authentication Parameters:", authentication_parameters, "Current Index:", index)
        # Privacy Parameters (OCTET STRING 0x04)
        privacy_parameters, index = self.parse_octet_string(data, index)
        if DEBUG_parse_snmpv3_packet: print("[parse_snmpv3_packet]Privacy Parameters:", privacy_parameters, "Current Index:", index)
        # SEQUENCE (0x30)
        length, index = self.parse_sequence(data, index)
        if DEBUG_parse_snmpv3_packet: print("[parse_snmpv3_packet]Context Length:", length, "Current Index:", index)
        # Context Engine ID (OCTET STRING 0x04)
        context_engine_id, index = self.parse_octet_string(data, index)
        if DEBUG_parse_snmpv3_packet: print("[parse_snmpv3_packet]Context Engine ID:", context_engine_id, "Current Index:", index)
        # Context Name (OCTET STRING 0x04)
        context_name, index = self.parse_octet_string(data, index)
        if DEBUG_parse_snmpv3_packet: print("[parse_snmpv3_packet]Context Name:", context_name, "Current Index:", index)
        
        # Now expecting GetRequest PDU
        # Pdu Type
        pdu_type = data[index]
        if DEBUG_parse_snmpv3_packet: print("[parse_snmpv3_packet]Pdu Type:", pdu_type, "Current Index:", index)
        # Request ID (INTEGER 0x02)
        index += 2
        request_id, index = self.parse_integer(data, index)
        if DEBUG_parse_snmpv3_packet: print("[parse_snmpv3_packet]Request ID:", request_id, "Current Index:", index)
        # Error Status (INTEGER 0x02)
        error_status, index = self.parse_integer(data, index)
        if DEBUG_parse_snmpv3_packet: print("[parse_snmpv3_packet]Error Status:", error_status, "Current Index:", index)
        # Error Index (INTEGER 0x02)
        error_index, index = self.parse_integer(data, index)
        if DEBUG_parse_snmpv3_packet: print("[parse_snmpv3_packet]Error Index:", error_index, "Current Index:", index)

        # Parse the Variable Bindings SEQUENCE
        # SEQUENCE (0x30)
        length, index = self.parse_sequence(data, index)
        oid = None
        value = None
        if(length != 0):
            # SEQUENCE (0x30)
            length, index = self.parse_sequence(data, index)
            if DEBUG_parse_snmpv3_packet: print("[parse_snmpv3_packet]Variable Bindings Length:", length, "Current Index:", index)
            # OID (0x06)
            oid, index = self.parse_oid(data, index)
            # Value (OCTET STRING 0x04)
            value, index = self.parse_octet_string(data, index)
        if DEBUG_parse_snmpv3_packet: print("[parse_snmpv3_packet]OID:", oid, "Value:", value, "Current Index:", index)
        return [version, \
                message_id, \
                max_msg_size, \
                flags, \
                security_model, \
                authoritative_engine_id, \
                authoritative_engine_boots, \
                authoritative_engine_time, \
                username, \
                authentication_parameters, \
                privacy_parameters, \
                context_engine_id, \
                context_name, \
                pdu_type, \
                request_id, \
                error_status, \
                error_index, \
                oid, \
                value]

    def parse_snmp_version(self, data):
        index = 0
        # Parse the SNMPv3 message header
        # SEQUENCE (0x30)
        length, index = self.parse_sequence(data, index)
        # SNMP Version (INTEGER 0x02)
        version, index = self.parse_integer(data, index)
        # print(length, version)
        return version

    def parse_snmp_request(self, *args):
        if(len(args) < 1):
            return None
        # 获取版本
        version = self.parse_snmp_version(args[0])
        if(version == None):
            return None
        # 解析SNMP请求
        if(version == 1):
            parse_data = self.parse_snmpv2_packet(args[0])
        elif(version == 3):
            parse_data = self.parse_snmpv3_packet(args[0])
        return parse_data
    
    def handle_snmp_request(self, *args):        
        if(len(args) < 1):
            return None
        # 获取版本
        arg = args[0]
        version = arg[0]
        if(version == None):
            return None
        # 解析SNMP请求
        pdu_type = None
        if(version == 1):
            pdu_type = arg[2]
        elif(version == 3):
            pdu_type = arg[13]
        else:
            return None
        snmp_response = None
        if pdu_type == 0xA0:  # GET 请求
            snmp_response = self.handle_get_request(*args[0])
        elif pdu_type == 0xA3:  # SET 请求
            snmp_response = self.handle_set_request(*args[0])
        else:
            return None
        return snmp_response

    def serve_forever(self):
        print("SNMP Agent is running on", self.host, ":", self.port, "...")

        while True:
            data = None
            parse_data = None
            snmp_response = None
            # 接收SNMP请求
            data, addr = self.socket.recvfrom(1024)  
            print("Received SNMP request from", "data:", data, "datalen:", len(data), "addr:", addr)
            # 解析SNMP请求
            if(data != None):
                parse_data = self.parse_snmp_request(data)
            # 处理SNMP请求
            if(parse_data != None):
                snmp_response = self.handle_snmp_request(parse_data)
            print("snmp_response:", snmp_response)
            # for i in range(len(snmp_response)):
            #     print(hex(snmp_response[i]))
            # 发送SNMP响应
            if(snmp_response != None):
                self.socket.sendto(snmp_response, addr)


# 使用SNMPAgent类
if __name__ == '__main__':
    stage, state = checkNet.waitNetworkReady(30)
    host = dataCall.getInfo(1, 0)[2][2]
    post = 161
    print("host:", host)
    agent = SNMPAgent(host, post)
    if stage == 3 and state == 1:  # Network connection is normal
        print('[net] Network connection successful.')
        _thread.start_new_thread(agent.serve_forever, ())
        print('sleep 3s to ensure that the server starts successfully.')
        utime.sleep(3)
    else:
        print('[net] Network connection failed, stage={}, state={}'.format(stage, state))

