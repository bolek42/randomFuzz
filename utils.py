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
import struct

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
        timeout = 10
        while True:
            t,pid = self.watchDogQueue.get()
            t2 = time.time()
            time.sleep(max(0,t+timeout-t2))
            try:
                os.kill(pid, 9)
                print "%d Hung" % pid
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
        self.call = self.call_sancov

    def call_sancov(self, data, ext):
        fname = None
        if "%s" in self.cmd:
            fname = "t-%016x.%s" % (getrandbits(64), ext)

            with open(fname, "w") as f:
                f.write(data)
            cmd = (self.cmd % fname).split(" ")
        else:
            cmd = (self.cmd).split(" ")

        os.environ["ASAN_OPTIONS"] = "coverage=1:symbolize=1"
        p = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE)
        self.watchDog.start(p.pid)

        if fname is not None:
            stdout, stderr = p.communicate(input="")
        else:
            stdout, stderr = p.communicate(input=data)

        crash, bitsets = self.parse_asan(p.pid, stderr)
        if fname is not None and os.path.exists(fname):
            os.remove(fname)

        return stdout+stderr, crash, bitsets

    def parse_asan(self, pid, stderr):
        bitsets = {}
        for sname in glob.glob("*.%d.sancov" % (pid)):
            f = open(sname)
            data = f.read()
            if struct.unpack("<Q", data[:8])[0] == 0xC0BFFFFFFFFFFF64:
                data = map(lambda x: struct.unpack("<Q", x)[0], [data[i:i+8] for i in range(0, len(data), 8)])
            else:
                data = map(lambda x: struct.unpack("<I", x)[0], [data[i:i+4] for i in range(0, len(data), 4)])

            bitsets[".".join(sname.split(".")[:-2])] = set(data)
            f.close()
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
            

    def call_qemu(self, data, ext):
        prefix = "t-%016x" % getrandbits(64)

        cmd = ["qemu-arm", "-trace", "translate_block,file=%s" % prefix, self.cmd]
        p = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE)
        self.watchDog.start(p.pid)

        stdout, stderr = p.communicate(input=data)

        cov = self.coverage(prefix)
        crash = self.coredump_qemu(p.pid)

        for fname in glob.glob(prefix+"*"):
            os.remove(fname)

        return stdout+stderr, crash, cov

    def coverage_qemu(self, fname):
        f = open(fname, "r")
        path = []
        for line in f:
            try:
                pc = re.findall("pc:0x[0-9a-f]*",line)[0][3:]
                path += [int(pc,16)]
            except:
                print line
                import traceback; traceback.print_exc()

        f.close()
        if len(path) < 2:
            return []

        return set(path)


    def coredump(self, pid):
        binary = os.path.basename(self.cmd)
        coredump = glob.glob("qemu_%s_*_%d.core" % (binary,pid))
        if len(coredump) != 0:
            try:
                import pwn
                pwn.context.log_level = 'error'
                c = pwn.Coredump(coredump[0])
                ret = ""
                ret += "pc=0x%x"%c.prstatus.pr_reg.pc
                ret += "lr=0x%x"%c.prstatus.pr_reg.lr
                #ret += "r0=0x%x"%c.prstatus.pr_reg.r0
                #ret += "r1=0x%x"%c.prstatus.pr_reg.r1
                #ret += "r2=0x%x"%c.prstatus.pr_reg.r2
                #ret += "r3=0x%x"%c.prstatus.pr_reg.r3
                #ret += "r4=0x%x"%c.prstatus.pr_reg.r4
                #ret += "r5=0x%x"%c.prstatus.pr_reg.r5
                #ret += "r6=0x%x"%c.prstatus.pr_reg.r6
                #ret += "r7=0x%x"%c.prstatus.pr_reg.r7
                #ret += "r8=0x%x"%c.prstatus.pr_reg.r8
                #ret += "r9=0x%x"%c.prstatus.pr_reg.r9
                #ret += "r10=0x%x"%c.prstatus.pr_reg.r10
                #ret += "r11=0x%x"%c.prstatus.pr_reg.r11
                #ret += "r12=0x%x"%c.prstatus.pr_reg.r12
                os.unlink(coredump[0])
                pc = c.prstatus.pr_reg.pc
                del c

                #if pc > 0xbeef000 and pc < 0xbeef000 + 10*1024 : #XXX
                #    return False
                return ret
            except:
                import traceback; traceback.print_exc() 

        return False


if __name__ == "__main__":
    q = executor("/home/hammel/hck/asanized/FFmpeg/ffmpeg -i %s out.mp4 -y", "/tmp")
    q.call("AAAAAA", "pdf")
