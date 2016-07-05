from randomFuzz import *
from utils import *
import os
from binascii import crc32, unhexlify, hexlify

def avprobe_callback(self, testcase):
    return callback_file( self, testcase, "./avprobe %s", "seed-1.mp4", None)

f = randomFuzz(     ["teststuff/libav/avprobe", "teststuff/libav/seed-1.mp4"],
                    "teststuff/fuzz/avprobe", 
                    [],
                    avprobe_callback)

f.add_mutator("data")
f.launch()

