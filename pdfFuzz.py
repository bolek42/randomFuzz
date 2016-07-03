from mutationFuzz import *
from randomFuzz import *
import os
from binascii import crc32, unhexlify

def seeds():
	return []

def mutate_callback(self, testcase):
    try:
        seed = self.seed
    except:
        with open("../seed-1.pdf", "r") as f:
            seed = f.read()
            self.seed = seed

    try:
        m = self.mutator
    except:
        m = mutator(seeds())
        self.mutator = m

    data = m.mutate_seed(testcase, seed)
    testcase["len"] = len(data)
    return data

os.chdir("teststuff")


f = randomFuzz(     ["evince-thumbnailer %s /dev/null"],
                    [],
                    seeds(),
                    "pdf-work", 
                    mutate_callback,
                    1338)
f.launch()

