from tlslite.api import *
from binascii import *
import socket
from mutator import *
from randomFuzz import *

from utils import *

#         _           _          __  __ 
# ___ ___| |      ___| |_ _   _ / _|/ _|
#/ __/ __| |_____/ __| __| | | | |_| |_ 
#\__ \__ \ |_____\__ \ |_| |_| |  _|  _|
#|___/___/_|     |___/\__|\__,_|_| |_|  

class TLSMessage(object):
    def __init__(self, content_type, data):
        self.contentType = content_type
        self.bytes = data

    def write(self):
        return self.bytes

class TLSExtension(object):
    def __init__(self, extType, data):
        self.extType = extType

        self.bytes = ""
        self.bytes += struct.pack(">H", self.extType)
        self.bytes += struct.pack(">H", len(self.bytes))
        self.bytes += data

    def write(self):
        return self.bytes


class Writer(object):
    def add(self, x, length):
        self.bytes += bytearray(length)
        newIndex = len(self.bytes) - 1
        for count in range(length):
            self.bytes[newIndex] = x & 0xFF
            x >>= 8
            newIndex -= 1
        if x != 0:
            raise ValueError("Can't represent value in specified length")

class TLSConnection_mutator(TLSConnection):
    def __init__(self, mutator, testcase, sock):
        #hook send method
        self._sendMsg_orig = self._sendMsg
        self._sendMsg = self.send_hook
        self._getMsg_orig = self._getMsg
        self._getMsg = self.get_hook
    
        #mutator
        self.mutator = mutator
        self.testcase = testcase

        #call init
        TLSConnection.__init__(self, sock)


    def send_hook(self, msg, randomizeFirstBlock=True):
        #print ">>>", type(msg).__name__, msg.contentType, hexlify(msg.write())
        data = msg.write()

        #mutate
        if type(msg).__name__ in self.testcase["mutators"]:
            mutator = self.testcase["mutators"][type(msg).__name__]
            if type(msg).__name__ == "ClientHello":
                #fuzzed extension
                mutator = self.testcase["mutators"]["Extension"]
                extdata = "\x00\x00" + "\x00"
                extdata = self.mutator.mutate_seed(mutator, extdata)
                extdata = "\x00" * max(0, 2 - len(extdata)) + extdata
                extType = struct.unpack("<H", extdata[:2])[0]
                ext = TLSExtension( extType, extdata[2:])
                msg.addExtension(ext)
                data = msg.write()

                mutator = self.testcase["mutators"]["ClientHello"]
                data = self.mutator.mutate_seed(mutator, data)


            #fuzz extension
            if type(msg).__name__ == "TLSMessage":
                data = chr(msg.contentType) + data
                data = self.mutator.mutate_seed(mutator, data)
                data = "\x00" * max(0, 1 - len(data)) + data
                msg.contentType = ord(data[0])
                data = data[1:]

            #print "Mut", type(msg).__name__, msg.contentType, hexlify(data)
            msg.write = lambda: data

        return self._sendMsg_orig(msg, randomizeFirstBlock)

    def get_hook(self, expectedType, secondaryType=None, constructorType=None):
        records = self._getMsg_orig(expectedType, secondaryType, constructorType)

        for x in records:
            #print "<<<", type(x).__name__, x.contentType, hexlify(x.write())
            yield x

#  __               
# / _|_   _ ________
#| |_| | | |_  /_  /
#|  _| |_| |/ / / / 
#|_|  \__,_/___/___|


import time
from subprocess import Popen, PIPE, STDOUT
import threading
from multiprocessing import Process
import struct

def fuzzClient(mutator, testcase, port=31337):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        i = 0
        while True:
            try:
                sock.connect( ("127.0.0.1", port) )
                break
            except:
                time.sleep(0.01)
                i += 1
                if i == 100:
                    return
        sock.settimeout(0.3)
        connection = TLSConnection_mutator(mutator, testcase, sock)

        connection.handshakeClientCert()
        connection.send("asd\n")

        msg = TLSMessage( 23, "B")
        1 in connection._sendMsg(msg)

        connection.close()
        sock.close()
    except TLSRemoteAlert as e:
        print e
    except TLSAbruptCloseError as e:
        print e
    except TLSLocalAlert as e:
        print e
    except TLSInternalError as e:
        print e
    except socket.error as e:
        print e
    except:
        pass
        import traceback; traceback.print_exc()

#calls testcase and returns results
def callback(self, testcase):
    port = randrange(10000,60000)
    cmd = ("./ssl_server %d" % port).split(" ")
    p = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE)
    self.watchDog.start(p.pid, [])

    threading.Thread(target=fuzzClient, args=(self.mutator, testcase, port)).start()

    stdout, stderr = p.communicate(input="")
    crash, bitsets = parse_asan(p.pid, stderr)

    return stderr, crash, bitsets


if __name__ == "__main__":


    f = randomFuzz(     ["teststuff/ssl_server","teststuff/server.pem"],
                        "teststuff/ssl-work", 
                        [],#seeds
                        callback,
                        1337)

    f.add_mutator("ClientHello")
    f.add_mutator("Extension")
    #f.add_mutator("ClientKeyExchange")
    #f.add_mutator("ChangeCipherSpec")
    #f.add_mutator("Finished")
    #f.add_mutator("ApplicationData")
    f.add_mutator("TLSMessage")

    #callback(f, f.initial_testcase)
    #sys.exit(1)

    f.launch()

    #m = mutator([])
    #testcase = {"len": 128, "id": 0, "mutations": []}

    #for i in xrange( 6):
    #    testcases = {i: testcase}
    #    execute_testcases(m, testcases) #determine length
    #
    #    mutated = m.get_random_mutations(testcase)
    #    testcases = {i: mutated}
    #    execute_testcases(m, testcases)
    #
    #while True:
    #    mutated = m.get_random_mutations(testcase)
    #    testcases = {3: mutated}
    #    try:
    #        execute_testcases(m, testcases)
    #    except:
    #        pass


