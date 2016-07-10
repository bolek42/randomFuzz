from randomFuzz import *
from utils import *
import os
from binascii import crc32, unhexlify, hexlify
import sys
from copy import deepcopy
from random import *

if len(sys.argv) < 4:
    print "usage: %s seed workdir port" % sys.argv[0]
    print "usage: %s seed workdir port testcase" % sys.argv[0]
    sys.exit(1)

seed = sys.argv[1]
workdir = sys.argv[2]
port = int(sys.argv[3])
if len(sys.argv) == 5:
    testcase = load_json(sys.argv[4])

cmd = "./avconv -i %s /tmp/null.mp4 -y"

def avprobe_callback(self, testcase):
    return callback_file( self, testcase, cmd, os.path.basename(seed), None)

def process_cash( self, testcase, seed):
    os.environ["ASAN_OPTIONS"]="halt_on_error=0"
    addrs = []

    stderr, crash, bitsets = callback_file( self, testcase, cmd, os.path.basename(seed), None, dumpfile="/tmp/crash-min.mp4")
    #fuzz crash
    while True:
        mutated = self.mutator.get_random_mutations( testcase , maximum=1)#, start=711-16, stop=711+16, mutations=[3])
        stderr, crash, bitsets = callback_file( self, mutated, cmd, os.path.basename(seed), None)
        for line in stderr.split("\n"):
            if "ERROR: AddressSanitizer:" in line: 
                try:
                    addr = re.findall("on [a-z ]*address 0x[0-9a-f]*", line)[0]
                    addr = re.findall("0x[0-9a-f]*", addr)[0]
                    if addr not in addrs:
                        if "READ" in stderr:
                            stderr, crash, bitsets = callback_file( self, mutated, cmd, os.path.basename(seed), None, dumpfile="/tmp/crash-%s-read.mp4" % addr)
                            print "READ", addr, mutated["description"]
                        else:
                            stderr, crash, bitsets = callback_file( self, mutated, cmd, os.path.basename(seed), None, dumpfile="/tmp/crash-%s-write.mp4" % addr)
                            print "WRITE", addr, mutated["description"]
                        addrs += [addr]
                except:
                    print stderr
                    stderr, crash, bitsets = callback_file( self, mutated, cmd, os.path.basename(seed), None, dumpfile="/tmp/crash-%s.mp4" % "other")
        


f = randomFuzz(     ["teststuff/libav/avprobe", seed],
                    workdir,
                    [],
                    avprobe_callback,
                    port)

f.add_mutator("data")

if len(sys.argv) == 4:
    f.launch()
else:
    process_cash(f, testcase, seed)
