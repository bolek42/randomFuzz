import sys
import os
import getopt
import json

from master import master
from worker import worker

_doc_="""
randomFuzz.py fuzz              --cmd=cmd --dir=workdir --seed=seed --port=port files
randomFuzz.py fuzz-restore      --dir=workdir
randomFuzz.py work              --dir=workdir --ip=ip ports
randomFuzz.py crash-fuzz        --dir=testdir crashes
randomFuzz.py select-testcases  --cmd=cmd --dir=testdir  files

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
        usage()

if what in ("fuzz-restore", "crash-fuzz"):
    print "reolding config..."
    with open("%s/cfg.json" % workdir, "r") as f:
        cfg = json.loads(f.read())
        cmd = cfg["cmd"]
        args = map(lambda x: "%s/%s" % (workdir, x), cfg["files"]+args)
        seed = cfg["seed"]
        port = cfg["port"]
        
if what in ("fuzz","fuzz-restore"):
    cfg = {}
    cfg["cmd"] = cmd
    cfg["files"] = map(os.path.basename, args)
    cfg["seed"] = os.path.basename(seed)
    cfg["port"] = port

    if not os.path.exists(workdir):
        os.makedirs(workdir)

    with open("%s/cfg.json" % workdir, "w") as f:
        f.write(json.dumps(cfg))

    files = args
    f = master( cmd, files, workdir, [])

    with open(seed, "rb") as x:
        l = len(x.read())
    f.add_mutator("data", l)
    f.fuzz(seed, port)

elif what == "work":
    #set up workers
    if len(args) == 1:
        try:
            w = worker(ip,int(port), "%s/%d" % (workdir, int(port)), n_threads=threads, mutations=mutations)
            w.provision()
            w.run()
        except:
            w.stop()
            import traceback; traceback.print_exc()
            os.kill(os.getpid(), 9)
    else:
        cwd = os.getcwd()
        workers = []
        for port in args:
            os.chdir(cwd)
            w = worker(ip,int(port), "%s/%d" % (workdir, int(port)), n_threads=threads, mutations=mutations)
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

elif what == "select-testcases":
    files = args
    f = master( cmd, files, workdir, [])
    f.add_mutator("data")
    f.select_testcases()

elif what == "crash-fuzz":
    print cmd
    f = master(cmd, [], workdir, [])
    f.seed = seed
    files = map(os.path.basename, args[1:])
    print files
    f.crash_fuzz(files)

else:
    usage()

