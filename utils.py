import glob
from multiprocessing import Process,Queue,cpu_count
from subprocess import Popen, PIPE, STDOUT
import time
import os
import json
from random import getrandbits
import re

#watchdog terminates processes after timeout
#and delete left files
class watchDog:
    def __init__(self, workdir):
        self.workdir=workdir
        self.watchDogQueue = Queue()
        d = Process(target=self.watchdog, args=())
        d.daemon=True
        d.start()
        self.process = d

    def start(self, pid, files):
            self.watchDogQueue.put((time.time(), pid, files))

    def exit(self):
        print "terminating watchdog"
        self.process.terminate()

    def watchdog(self):
        print "watchdog started"
        os.chdir(self.workdir)
        timeout = 1
        while True:
            t,pid,files = self.watchDogQueue.get()
            t2 = time.time()
            time.sleep(max(0,t+timeout-t2))
            try:
                os.kill(pid, 9)
                #print "%d Hung" % pid
            except:
                pass
            for fname in files:
                try:
                    os.remove(fname)
                except:
                    print "Watchdog work dir %s" % os.getcwd()
                    import traceback; traceback.print_exc()

#parses asan and bitset files
def parse_asan(pid, stderr):
    bitsets = {}
    for sname in glob.glob("*.%d.bitset-sancov" % (pid)):
        f = open(sname)
        bitsets[".".join(sname.split(".")[:-2])] = int("1"+f.read(),2)
        f.close()
        os.remove(sname)

    for sname in glob.glob("*.%d.sancov" % (pid)):
        os.remove(sname)

    # log crash
    crash = False
    if "ERROR: AddressSanitizer:" in stderr:
        try:
            errorline = re.findall( "ERROR\: AddressSanitizer: .*", stderr)[0]
            crash = re.findall("pc 0x[0-9a-f]*", errorline)[0][3:]
            errorline += ("#"*0x42)+"\n"+errorline+"\n"+("#"*0x42)
        except:
            crash = "0x42424242"

    return crash, bitsets

def save_json(fname, data):
    with open(fname, "w") as f:
        f.write(json.dumps(data))

def save_data(fname, data):
    with open(fname, "w") as f:
        f.write(data)

def load_json(fname):
    with open(fname, "r") as f:
        return json.loads(f.read())

def callback_file(self, testcase, postprocess_callback=None, dumpfile=None, execute=True):
    try:
        seed_data = self.seed_data
    except:
        with open(self.seed, "r") as f:
            seed_data = f.read()
            self.seed_data = seed_data

    m = self.mutator

    data = m.mutate_seed(testcase["mutators"]["data"], seed_data)
    if postprocess_callback:
        data = postprocess_callback(data)

    if dumpfile:
        with open( dumpfile, "w") as f:
            f.write(data)

    if not execute:
        return "", False, {}

    fname = hex(getrandbits(64))
    with open( fname, "w") as f:
        f.write(data)

    cmd = (self.cmd % fname).split(" ")
    p = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE)
    self.watchDog.start(p.pid, [fname])

    stdout, stderr = p.communicate(input="")
    crash, bitsets = parse_asan(p.pid, stderr)

    return stderr, crash, bitsets

