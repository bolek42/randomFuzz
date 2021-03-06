import os
import sys
import glob
from shutil import copy2

from utils import *

from api import api

class selector(api):
    def __init__(self, cfg, workdir):
        self.cmd = cfg["cmd"]
        for k in cfg["env"]:
            os.environ[k] = cfg["env"][k]

        self.workdir = os.path.abspath(workdir)
        self.executor = executor(self.cmd, self.workdir+"/run")

    def minimize(self, data):
        _,_,coverage = self.executor.call(data, self.ext)

        l = len(data)
        blocksize = 2**(len(data)-1).bit_length()
        while blocksize > 128:# > len(data):
            j = 0
            while j < len(data):
                sys.stderr.write("\rblocksize: %d len: %d/%d    " % (blocksize, len(data), l))
                min_data = data[:j] + data[j+blocksize:]
                _,_,c = self.executor.call(min_data, self.ext)

                if self.compute_new_blocks(coverage, c) == 0:
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
                            _,_,c = self.executor.call(data, self.ext)
                    except:
                        continue

                    hit = len(c)
                    
                    t = time.time() - start
                    print "%fs for %s (%d hit)" % (t, fname, hit)
                    results += [(fname, c, t, len(data), 0)]
        except KeyboardInterrupt:
            pass

        #sort by size
        coverage = dict()
        tmp = []
        for fname,c,t,l,_ in sorted(results, key=lambda x: x[3]):
            new_blocks = self.compute_new_blocks(c, coverage)
            self.coverage_update(coverage, c)

            if new_blocks > 10:
                tmp += [[fname, c, t, l, new_blocks]]

        while len(results) > count + 10:
            #sort results by new blocks
            results = []
            coverage = dict()
            for fname, c, t, l, new_blocks in sorted(tmp, key=lambda x: x[4], reverse=True)[:-1]:
                new_blocks = self.compute_new_blocks(c, coverage)
                self.coverage_update(coverage, c)

                if new_blocks > 10:
                    results += [[fname, c, t, l, new_blocks]]
                #print "New blocks %d, time: %.4fs, file: %s" % (new_blocks, t, fname)

            tmp = results

        i = 0
        for fname, c, t, l, new_blocks in sorted(results, key=lambda x: x[4], reverse=True)[:count]:
            print "New blocks %d, time: %.4fs, len: %d: file: %s" % (new_blocks, t, l, fname)
            for f in glob.glob("%s/seeds/seed-min-%d.*" %  (self.workdir,i)):
                os.remove(f)

            ext = fname.split(".")[-1]
            copy2("/tmp/minimized-%s" % fname, "%s/seeds/seed-min-%d.%s" % (self.workdir,i,ext))
            i += 1
