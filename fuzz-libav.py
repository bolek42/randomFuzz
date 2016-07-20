from randomFuzz import *
from utils import *
import os
from binascii import crc32, unhexlify, hexlify
import sys
from copy import deepcopy
from random import *


cmd = "./avconv-git -i %s /tmp/null.mp4 -y"

def avprobe_callback(self, testcase, dumpfile=None, execute=True):
    return callback_file( self, testcase, cmd, dumpfile=dumpfile, execute=execute)


def process_crash(self, stderr, testcase):
    for line in stderr.split("\n"):
        if "ERROR: AddressSanitizer:" in line: 
            try:
                addr = re.findall("on [a-z ]*address 0x[0-9a-f]*", line)[0]
                addr = re.findall("0x[0-9a-f]*", addr)[0]
                if addr not in self.addrs:
                    if "READ" in stderr:
                        cause = "READ"
                    else:
                        cause = "WRITE"

                    stderr, crash, bitsets = avprobe_callback( self, testcase, dumpfile="/tmp/crash-%s-%s.mp4" % (addr,cause))
                    save_data("/tmp/crash-%s-write.stderr" % addr, stderr)
                    print cause, addr, testcase["description"]
                    self.addrs += [addr]
                    self.crashes += [testcase]
            except:
                print stderr
                stderr, crash, bitsets = callback_file( self, testcase, cmd, os.path.basename(seed), None, dumpfile="/tmp/crash-%s.mp4" % "other")


def crash_fuzz( self, crashes):
    self.addrs = []
    self.crashes = []

    for i in xrange(len(crashes)):
        stderr, crash, bitsets = avprobe_callback( self, crashes[i], dumpfile="/tmp/crash-%d.mp4" % i)
        process_crash(self, stderr, crashes[i])

    #fuzz crash
    while True:
        testcase = choice( self.crashes)
        mutated = self.mutator.get_random_mutations( testcase , maximum=1)#, mutations=[3]) ##, start=711-16, stop=711+16)
        stderr, crash, bitsets = avprobe_callback( self, mutated)
        process_crash(self, stderr, mutated)

import glob
import time
from shutil import copy2
def select_testcases(path):
    os.environ["ASAN_OPTIONS"]="coverage=1:coverage_bitset=1:symbolize=1"

    #determine execution time for each file
    files = []
    for fname in glob.glob(path):
        start = time.time()
        for i in xrange(100):
            cmd = "./avconv-git -i %s /tmp/null.mp4 -y"
            cmd = (cmd % fname).split(" ")

            p = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(input="")
            _, b = parse_asan(p.pid, stderr)
        t = time.time() - start
        print "%fs for %s" % (t, fname)
        files += [(fname,t, b)]

    #determeine new codeblocks for each testfile, sorted by execution time
    bitsets = {}
    results = []
    for fname,t,b in sorted(files, key=lambda x: x[1]):
        new_blocks = 0
        for s in b:
            if s not in bitsets:
                bitsets[s] = 0

            new_blocks += bin((~bitsets[s]) & b[s]).count("1")
            bitsets[s] |= b[s]

        if new_blocks > 0:
            results += [[fname, new_blocks, t]]

    print "Final results:"
    threshold = 100
    i = 0
    for fname, new_blocks, t in sorted(results, key=lambda x: x[1], reverse=True):
        print "New blocks %d, time: %.4fs, file: %s" % (new_blocks, t, fname)
        if new_blocks > threshold:
            copy2(fname, "/tmp/seed-min-%d.mp4" % i)
            i += 1
    
        
#select_testcases("teststuff/mp4-seeds/*.mp4")
#sys.exit(1)

if len(sys.argv) < 4:
    print "usage: %s seed workdir port" % sys.argv[0]
    print "usage: %s seed workdir port testcase1 testcase2 ..." % sys.argv[0]
    sys.exit(1)


#parse args
seed = sys.argv[1]
workdir = sys.argv[2]
port = int(sys.argv[3])
if len(sys.argv) >= 5:
    crashes = []
    for fname in sys.argv[4:]:
        crashes += [load_json(fname)]


f = randomFuzz(     ["teststuff/libav/avprobe", "teststuff/libav/avconv-git", seed],
                    os.path.basename(seed),
                    workdir,
                    [],
                    avprobe_callback,
                    port)

f.add_mutator("data")

if len(sys.argv) == 4:
    f.launch()
else:
    crash_fuzz(f, crashes)
