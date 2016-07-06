from randomFuzz import *
from utils import *
import os
from binascii import crc32, unhexlify, hexlify
import sys

if len(sys.argv) < 3:
    print "usage: %s seed workdir [port]" % sys.argv[0]
    print "usage: %s seed workdir testcase" % sys.argv[0]
    sys.exit(1)

seed = sys.argv[1]
workdir = sys.argv[2]

def avprobe_callback(self, testcase):
    return callback_file( self, testcase, "./avprobe %s", os.path.basename(seed), None)

f = randomFuzz(     ["teststuff/libav/avprobe", seed],
                    workdir,
                    [],
                    avprobe_callback)

f.add_mutator("data")
f.launch()

def process_cash( self, testcase, seed):
    os.environ["ASAN_OPTIONS"]="halt_on_error=0"
    while True:
        mutated = self.mutator.get_random_mutations( testcase ,maximum=4)
        stderr, crash, bitsets = callback_file( self, mutated, "./avprobe %s", os.path.basename(seed), None)
        for line in stderr.split("\n"):
            if "of size" in line: 
                print line

testcase = load_json(sys.argv[3])
process_cash(f, testcase, seed)
