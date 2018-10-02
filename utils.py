import glob
from multiprocessing import Process,Queue,cpu_count
from subprocess import Popen, PIPE, STDOUT
import time
import os
import json
from random import getrandbits
import re
import sys
import r2pipe

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

    def call(self, data, ext):
        prefix = "t-%016x" % getrandbits(64)
        fname = "%s.%s" % (prefix, ext)
        with open( fname, "w") as f:
            f.write(data)

        cmd = (self.cmd % fname).split(" ")
        cmd = ["qemu-x86_64", "-trace", "translate_block,file=%s" % prefix] + cmd
        p = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE)
        self.watchDog.start(p.pid)

        stdout, stderr = p.communicate(input="")

        cov = self.coverage(prefix)
        crash = self.coredump(p.pid)

        for fname in glob.glob(prefix+"*"):
            os.remove(fname)

        return stdout+stderr, crash, cov

    def coverage(self, fname):
        f = open(fname, "r")
        cov = []
        for line in f:
            try:
                pc = re.findall("pc:0x[0-9a-f]*",line)[0][3:]
                cov += [int(pc,16)]
            except:
                print line
                import traceback; traceback.print_exc()

        f.close()
        return set(cov)

    def coredump(self, pid):
        coredump = glob.glob("qemu_*_%d.core" % pid)
        if len(coredump) != 0:
            r = r2pipe.open(coredump[0])
            os.unlink(coredump[0])
            ret = r.cmd("dr")
            return ret
            #print ret
            #pc = re.findall("rip.*=.*0x[0-9a-f]*",ret)[0]
            #return re.findall("0x[0-9a-f]*",pc)[0]

        return False


if __name__ == "__main__":
    with open("teststuff/pdfs/RES_V76K9ZF_AKUN9CL44276_0.pdf", "r") as f:
        data = f.read()

    #q = executor("/usr/bin/evince-thumbnailer %s test", "/tmp")
    q = executor("/home/hammel/hck/randomFuzz/qemutest/segv %s test", "/tmp")
    print q.call(data, "pdf")[1]
