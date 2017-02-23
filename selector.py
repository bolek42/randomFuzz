import os
import sys
import glob
from shutil import copy2

from utils import *


class selector:
    def __init__(self, cfg, workdir):
        self.cmd = cfg["cmd"]
        for k in cfg["env"]:
            os.environ[k] = cfg["env"][k]

        self.workdir = os.path.abspath(workdir)
        self.executor = executor(self.cmd, self.workdir+"/run")

    def minimize(self, data):
        _,_,bitsets = self.executor.call_sancov(data, self.ext)

        l = len(data)
        blocksize = 2**(len(data)-1).bit_length()
        while blocksize * 128 > len(data):
            j = 0
            while j < len(data):
                sys.stderr.write("\rblocksize: %d len: %d/%d    " % (blocksize, len(data), l))
                min_data = data[:j] + data[j+blocksize:]
                _,_,b = self.executor.call_sancov(min_data, self.ext)
                equal = True
                try:
                    for s in bitsets:
                        if bin(bitsets[s]).count("1") > bin(b[s]).count("1"):
                            equal = False
                except:
                    equal = False

                if equal:
                    data = min_data
                else:
                    j += blocksize

            blocksize /= 2
        sys.stderr.write("\n")

        return data

    def select_testcases(self, seeddirs, count=10):
        #determine execution time for each file
        results = []
        try:
            for seeddir in seeddirs:
                for fname in glob.glob(seeddir+"/*"):
                    with open(fname, "rb") as f:
                        data = f.read()
                    self.ext = fname.split(".")[-1]

                    data = self.minimize(data)
                    fname = os.path.basename(fname)
                    with open("/tmp/minimized-%s" % fname, "wb") as f:
                        f.write(data)

                    start = time.time()
                    try:
                        for i in xrange(1):
                            _,_,b = self.executor.call_sancov(data, self.ext)
                    except:
                        continue

                    hit, missed = 0, 1
                    for s in b:
                        hit += bin(b[s]).count("1")
                        missed += bin(b[s]).count("0")
                    
                    t = time.time() - start
                    print "%fs for %s (%d hit %.2f%%)" % (t, fname, hit, (hit*100.)/(hit+missed))
                    results += [(fname, b, t, len(data), 0)]
        except KeyboardInterrupt:
            pass

        #sort by size
        bitsets = {}
        tmp = []
        for fname,b,t,l,_ in sorted(results, key=lambda x: x[3]):
            new_blocks = 0
            for s in b:
                if s not in bitsets:
                    bitsets[s] = 0

                new_blocks += bin((~bitsets[s]) & b[s]).count("1")
                bitsets[s] |= b[s]

            if new_blocks > 10:
                tmp += [[fname, b, t, l, new_blocks]]

        while len(results) > count + 10:
            #sort results by new blocks
            results = []
            bitsets = {}
            for fname, b, t, l, new_blocks in sorted(tmp, key=lambda x: x[4], reverse=True)[:-1]:
                new_blocks = 0
                for s in b:
                    if s not in bitsets:
                        bitsets[s] = 0

                    new_blocks += bin((~bitsets[s]) & b[s]).count("1")
                    bitsets[s] |= b[s]

                if new_blocks > 10:
                    results += [[fname, b, t, l, new_blocks]]
                #print "New blocks %d, time: %.4fs, file: %s" % (new_blocks, t, fname)

            tmp = results

        i = 0
        for fname, b, t, l, new_blocks in sorted(results, key=lambda x: x[4], reverse=True)[:count]:
            print "New blocks %d, time: %.4fs, len: %d: file: %s" % (new_blocks, t, l, fname)
            for f in glob.glob("%s/seeds/seed-min-%d.*" %  (self.workdir,i)):
                os.remove(f)

            ext = fname.split(".")[-1]
            copy2("/tmp/minimized-%s" % fname, "%s/seeds/seed-min-%d.%s" % (self.workdir,i,ext))
            i += 1
