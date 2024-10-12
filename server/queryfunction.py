# Copyright (c) Quectel Wireless Solution, Co., Ltd.All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from misc import Power
import osTimer
import net
import dataCall

Function_READ = 0
Function_WRITE = 1

class TypeConvert(object):
    def str_to_bool(self, s):
        if s.lower() in ('true', '1'):
            return True
        elif s.lower() in ('false', '0'):
            return False
        else:
            return None

    def str_to_int(self, s):
        try:
            integer_value = int(s)
            return integer_value
        except:
            return None

class QueryFunction(object):

    def __init__(self):
        self.typeconvert = TypeConvert()
        self.keepAlive_second = 0
        self.func_map = {
            "Reboot": 'False',
            "keepAliveDuration": '0',
            "Operator": '('', '', '', '')',
            "APN": '',
            "pwshute_en": 'False',
        }
        timer = osTimer()
        timer.start(1000, 1, self._keepAlive_second_cb)

    def _keepAlive_second_cb(self, arg):
        self.keepAlive_second = self.keepAlive_second + 1

    def _Reboot(self, RWFlag = Function_READ, *args):
        ret = 0
        if len(args) < 1 and RWFlag == Function_WRITE:
            return [0, -1, None]
        if(RWFlag == Function_READ):
            return [0, 0, self.func_map["Reboot"]]
        elif(RWFlag == Function_WRITE):
            if isinstance(args[0], str):
                ret = self.typeconvert.str_to_bool(args[0])
            else:
                return [0, -2, None]
            if (ret != None):
                if(ret == True):
                    self.func_map["Reboot"] = 'False'
                    Power.powerRestart()
            else:
                return [0, -2, None]
        return [0, 0, 0]

    def _keepAliveDuration(self, RWFlag = Function_READ, *args):
        ret = 0
        if len(args) < 1 and RWFlag == Function_WRITE:
            return [0, -1, None]
        if(RWFlag == Function_READ):
            ret = self.typeconvert.str_to_int(self.func_map["keepAliveDuration"])
            ret += self.keepAlive_second
            return [0, 0, str(ret)]
        elif(RWFlag == Function_WRITE):
            if isinstance(args[0], str):
                ret = self.typeconvert.str_to_int(args[0])
            else:
                return [0, -2, None]
            if (ret != None):
                self.func_map["keepAliveDuration"] = str(ret - self.keepAlive_second)
            else:
                return [0, -2, None]
        return [0, 0, 0]

    def _Operator(self, RWFlag = Function_READ, *args):
        if len(args) < 1 and RWFlag == Function_WRITE:
            return [0, -1, None]
        if(RWFlag == Function_READ):
            self.func_map["Operator"] = str(net.operatorName())
            return [0, 0, self.func_map["Operator"]]
        elif(RWFlag == Function_WRITE):
            return [0, -3, None]
        return [0, 0, 0]

    def _APN(self, RWFlag = Function_READ, *args):
        ret = 0
        if len(args) < 1 and RWFlag == Function_WRITE:
            return [0, -1, None]
        if(RWFlag == Function_READ):
            PDPContext = dataCall.getPDPContext(1)
            self.func_map["APN"] = "{},{},{}".format(PDPContext[1],PDPContext[2],PDPContext[3])
            return [0, 0, self.func_map["APN"]]
        elif(RWFlag == Function_WRITE):
            if isinstance(args[0], str):
                if(len(args[0].split(",")) < 3):
                    return [0, -1, None]
                apn, username, password = args[0].split(",")
                self.func_map["APN"] = "{},{},{}".format(apn, username, password)
                PDPContext = dataCall.getPDPContext(1)
                ret = dataCall.setPDPContext(1, PDPContext[0], apn, username, password, PDPContext[4])
            else:
                return [0, -2, None]
        return [0, 0, ret]

    def _pwshute_en(self, RWFlag = Function_READ, *args):
        ret = 0
        if len(args) < 1 and RWFlag == Function_WRITE:
            return [0, -1, None]
        if(RWFlag == Function_READ):
            return [0, 0, self.func_map["pwshute_en"]]
        elif(RWFlag == Function_WRITE):
            if isinstance(args[0], str):
                ret = self.typeconvert.str_to_bool(args[0])
            else:
                return [0, -2, None]
            if(ret != None):
                self.func_map["pwshute_en"] = args[0]
            else:
                return [0, -2, None]
        return [0, 0, ret]

    def _readorwrite(self, RWFlag = Function_READ, *args):
        # 检查参数是否为空
        if len(args) < 1:
            return [-1, None, None]
        if len(args) < 2 and RWFlag == Function_WRITE:
            return [-1, None, None]
        # 构造方法名
        method = "_%s" % args[0]
        # 调用方法
        if hasattr(self, method):
            if(RWFlag == Function_READ):
                return getattr(self, method)(RWFlag)
            else:
                return getattr(self, method)(RWFlag, *args[1])
        else:
            return [-2, None, None]

    def read(self, *args):
        return self._readorwrite(Function_READ, *args)

    def write(self, *args):
        return self._readorwrite(Function_WRITE, *args)
