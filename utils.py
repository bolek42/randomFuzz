import glob
from multiprocessing import Process,Queue,cpu_count
from subprocess import Popen, PIPE, STDOUT
import time
import os
import json
from random import getrandbits
import re
import sys
from binascii import hexlify

#watchdog terminates processes after timeout
#and delete left files
class watchDog:
    def __init__(self):
        self.watchDogQueue = Queue()
        d = Process(target=self.watchdog, args=())
        d.daemon=True
        d.start()
        self.process = d

    def start(self, pid):
            self.watchDogQueue.put((time.time(), pid))

    def exit(self):
        print "terminating watchdog"
        self.process.terminate()

    def watchdog(self):
        print "watchdog started"
        timeout = 1
        while True:
            t,pid = self.watchDogQueue.get()
            t2 = time.time()
            time.sleep(max(0,t+timeout-t2))
            try:
                os.kill(pid, 9)
                #print "%d Hung" % pid
            except:
                pass

#parses asan and bitset files

def save_json(fname, data):
    j = json.dumps(data)
    with open(fname, "w") as f:
        f.write(j)

def save_data(fname, data):
    with open(fname, "w") as f:
        f.write(data)

def load_json(fname):
    with open(fname, "r") as f:
        return json.loads(f.read())

class executor:
    def __init__(self, cmd, workdir):
        os.chdir(workdir)
        self.watchDog = watchDog()
        self.cmd = cmd

    def call_sancov(self, data, ext):
        fname = "t-%016x.%s" % (getrandbits(64), ext)
        #with open( fname, "w") as f:
        #    f.write(data)

        cmd = (self.cmd ).split(" ")
        p = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE)
        self.watchDog.start(p.pid)

        stdout, stderr = p.communicate(input=data)
        crash, bitsets = self.parse_asan(p.pid, stderr)
        if os.path.exists(fname):
            os.remove(fname)

        return stderr, crash, bitsets

    def parse_asan(self, pid, stderr):
        bitsets = {}
        for sname in glob.glob("*.%d.sancov" % (pid)):
            f = open(sname)
            bitsets[".".join(sname.split(".")[:-2])] = int("0x1" + hexlify(f.read()),16)
            f.close()
            os.remove(sname)

        for sname in glob.glob("*.%d.sancov" % (pid)):
            os.remove(sname)

        # log crash
        crash = False
        cause = ""
        if "ERROR: AddressSanitizer:" in stderr:
            try:
                errorline = re.findall( "[ ]*#0 0x[0-9a-f]*[ ]*(.*\+0x[0-9a-f]*)", stderr)[0]
                crash = re.findall("0x[0-9a-f]*", errorline)[0]
            except:
                crash = "0x42424242"

            cause = "OTHER"
            if "READ" in stderr:
                cause = "READ"#re.findall("READ of size [0-9]*", stderr)[0]
            elif "WRITE" in stderr:
                cause = "WRITE"#re.findall("WRITE of size [0-9]*", stderr)[0]

            crash = "%s-%s" % (crash, cause)

        return crash, bitsets

