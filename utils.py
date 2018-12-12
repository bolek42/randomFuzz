import glob
from multiprocessing import Process,Queue,cpu_count
from subprocess import Popen, PIPE, STDOUT
import time
import os
import json
from random import getrandbits
import re
import sys
import pwn

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
        pwn.context.log_level = 'error'

    def call(self, data, ext):
        prefix = "t-%016x" % getrandbits(64)

        cmd = ["qemu-arm", "-trace", "translate_block,file=%s" % prefix, self.cmd]
        p = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE)
        self.watchDog.start(p.pid)

        stdout, stderr = p.communicate(input=data)

        cov = self.coverage(prefix)
        crash = self.coredump(p.pid)

        for fname in glob.glob(prefix+"*"):
            os.remove(fname)

        return stdout+stderr, crash, cov

    def coverage(self, fname):
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

        edges = []
        prev = path[0]
        for node in path[1:]:
            edge = prev << 32 | node
            edges += [edge]

        return set(edges)

    def coredump(self, pid):
        binary = os.path.basename(self.cmd)
        coredump = glob.glob("qemu_%s_*_%d.core" % (binary,pid))
        if len(coredump) != 0:
            try:
                c = pwn.Coredump(coredump[0])
                ret = ""
                ret += "pc=0x%x"%c.prstatus.pr_reg.pc
                ret += "lr=0x%x"%c.prstatus.pr_reg.lr
                ret += "r0=0x%x"%c.prstatus.pr_reg.r0
                ret += "r1=0x%x"%c.prstatus.pr_reg.r1
                ret += "r2=0x%x"%c.prstatus.pr_reg.r2
                ret += "r3=0x%x"%c.prstatus.pr_reg.r3
                ret += "r4=0x%x"%c.prstatus.pr_reg.r4
                ret += "r5=0x%x"%c.prstatus.pr_reg.r5
                ret += "r6=0x%x"%c.prstatus.pr_reg.r6
                ret += "r7=0x%x"%c.prstatus.pr_reg.r7
                ret += "r8=0x%x"%c.prstatus.pr_reg.r8
                ret += "r9=0x%x"%c.prstatus.pr_reg.r9
                ret += "r10=0x%x"%c.prstatus.pr_reg.r10
                ret += "r11=0x%x"%c.prstatus.pr_reg.r11
                ret += "r12=0x%x"%c.prstatus.pr_reg.r12
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
    with open("teststuff/pdfs/RES_V76K9ZF_AKUN9CL44276_0.pdf", "r") as f:
        data = f.read()

    #q = executor("/usr/bin/evince-thumbnailer %s test", "/tmp")
    q = executor("/home/hammel/hck/randomFuzz/qemutest/segv %s test", "/tmp")
    print q.call(data, "pdf")[1]
