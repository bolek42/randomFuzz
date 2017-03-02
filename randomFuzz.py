import sys
import os
import getopt
import json
from shutil import copy2

from utils import *
from selector import selector
from master import master
from worker import worker

_doc_="""-=randomFuzz=-
randomFuzz.py init              --dir=workdir --cmd=cmd [files]
randomFuzz.py select-testcases  --dir=testdir seed-dir1 seed-dir2 ...
randomFuzz.py fuzz              --dir=workdir --port=port
randomFuzz.py show-state        --dir=workdir
randomFuzz.py work              --dir=workdir --ip=ip ports
randomFuzz.py crash-fuzz        --dir=testdir crashes

args:
\t-h, --help    this gelp
\t--port=       port
\t--ip=         ip
\t--seed=       seed
\t--dir=        work dir
\t--threads=    worker threads
\t--bitflip     bit- /byteflip only
"""

def usage():
    print _doc_
    sys.exit(1)

try:
    what = sys.argv[1]
    opt_short = "h"
    opt_long = ["help", "cmd=", "port=", "seed=", "dir=", "ip=", "threads=", "bitflip"]
    (opts,args) = getopt.getopt(sys.argv[2:], opt_short, opt_long)
except:
    import traceback; traceback.print_exc() 
    usage()

threads = 0
port = 1337
mutations = None
for o,v in opts:
    if o in ("-h", "--help"):
        usage()
    elif o in ("-c", "--cmd"):
        cmd = v
    elif o in ("-p", "--port"):
        port = int(v)
    elif o in ("-i", "--ip"):
        ip = v
    elif o in ("-s", "--seed"):
        args += [v]
        seed = os.path.basename(v)
    elif o in ("-d", "--dir"):
        workdir = v
    elif o in ("-t", "--threads"):
        threads = int(v)
    elif o in ("--bitflip"):
        mutations = [0,1]
    else:
        print o,v
        usage()

#config handling
if what == "init":
    #create workdir
    try:
        os.makedirs(workdir)
        os.makedirs("%s/seeds" % workdir)
        os.makedirs("%s/files" % workdir)
        os.makedirs("%s/run" % workdir)
        os.makedirs("%s/crash" % workdir)
    except:
        pass

    for fname in args:
        copy2(fname, "%s/files" % workdir)

    home = os.environ["HOME"]
    cfg = {}
    cfg["cmd"] = cmd
    cfg["files"] = map(os.path.basename, args)
    cfg["env"] = {}
    cfg["env"]["ASAN_OPTIONS"] = "coverage=1:coverage_bitset=1:symbolize=1"
    cfg["env"]["MALLOC_CHECK_"] = "0"
    cfg["env"]["PATH"] = "%s/asan-builds/bin/:%s/asan-builds/sbin/" % (home,home)
    cfg["env"]["LD_LIBRARY_PATH"] = "%s/asan-builds/lib/" % home

    save_json("%s/cfg.json" % workdir, cfg)
    
elif what == "select-testcases":
    cfg = load_json("%s/cfg.json" % workdir)
    seeddirs = map(os.path.abspath, args)
    s = selector(cfg, workdir)
    s.select_testcases(seeddirs)

elif what == "fuzz":
    cfg = load_json("%s/cfg.json" % workdir)
    f = master(cfg, workdir, port)
    for seed in glob.glob("seeds/*"):
        try:
            f.fuzz(seed)
        except KeyboardInterrupt:
            f.stop()
            try:
                time.sleep(1)
            except:
                os.kill(os.getpid(), 9)

elif what == "work":
    #set up worker
    if len(args) == 1:
        while True:
            try:
                w = worker("%s/run/%d" % (workdir, int(port)), n_threads=threads)
                w.connect(ip,int(port))
                w.run()
            except:
                import traceback; traceback.print_exc()
                w.stop()
            time.sleep(1)

    else:
        cwd = os.getcwd()
        workers = []
        for port in args:
            os.chdir(cwd)
            w = worker(ip,int(port), "%s/run/%d" % (workdir, int(port)), n_threads=threads, mutations=mutations)
            w.provision()
            workers += [w]

        try:
            while True:
                for i in xrange(len(workers)):
                    print ">>> Working on worker %d <<<" % i
                    workers[i].run(10000)
                    workers[i].stop()
            
        except:
            import traceback; traceback.print_exc()
            for w in workers:
                w.stop()
            os.kill(os.getpid(), 9)

elif what == "crash-fuzz":
    print cmd
    f = master(cmd, [], workdir, [])
    f.seed = seed
    files = map(os.path.basename, args[1:])
    print files
    f.crash_fuzz(files)

elif what != "init":
    usage()

