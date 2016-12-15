#!/usr/bin/env python2
import sys
import socket
import os
from multiprocessing import Process,Queue,cpu_count,Value
import json
from base64 import b64encode, b64decode
from random import getrandbits, randrange, choice
from subprocess import Popen, PIPE, STDOUT
import re
import struct
import pickle
import glob
from mutator import mutator
from utils import *
from copy import deepcopy
from shutil import copy2


class worker():
    def __init__(self, ip, port, workdir, n_threads=0):
        os.environ["ASAN_OPTIONS"]="coverage=1:coverage_bitset=1:symbolize=1"
        os.environ["MALLOC_CHECK_"]="0"
        os.environ["LD_LIBRARY_PATH"]="."

        self.ip = ip
        self.port = port
        self.workdir = os.path.abspath(workdir)
        self.n_threads = cpu_count() if n_threads == 0 else n_threads
        self.process_list = []

        self.bitsets = {}
        self.testcases = []
        self.executed_testcases = Value('i', 0)

        self.work_queue = Queue()
        self.testcase_count = Queue()
        self.update_queues = []

        self.testcase_report = Queue()
        self.watchDog = None

        #create workdir
        if not os.path.exists(self.workdir):
            os.makedirs(self.workdir)


    def provision(self):
        print "connecting %s:%d" % (self.ip, self.port)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(100000)
        s.connect((self.ip, self.port))
        self.sock = s

        #get provision json
        n = struct.unpack('<I',s.recv(4))[0]
        d = ""
        while len(d) < n:
            d += s.recv(n-len(d))
        provision = json.loads(d)
        del d

        #generic
        self.cmd = provision["cmd"]
        self.bitsets = provision["bitsets"]
        self.crash_addr = provision["crash_addr"]
        self.seed = provision["seed"]
        self.mutator = mutator(provision["seeds"])
        self.callback = pickle.loads(b64decode(provision["callback"]))

        for t in json.loads(b64decode(provision["testcases"])):
            self.testcases += [b64decode(json.loads(t))]

        #write Files to Disk
        os.chdir(self.workdir)
        for fname, data in provision["files"].iteritems():
            try:
                print "received %s %dkB" % (fname, len(data)/1024)
                f = open(fname, "w")
                f.write(b64decode(data))
                f.close()
                os.chmod(fname, 0700)
            except:
                import traceback; traceback.print_exc()

        #prepare workdir
        for fname in glob.glob("*sancov"):
            os.remove(fname)

        #fetch initial testcases
        print "Got %d initial testcases" % len(provision["initial_testcases"])
        for testcase in provision["initial_testcases"]:
            self.work_queue.put(testcase)

        #cleanup
        del provision
        print "privision done"

    def run(self, n_testcases=0):
        #prepare workdir
        os.chdir(self.workdir)
        for fname in glob.glob("*sancov"):
            os.remove(fname)

        #start worker threads
        self.watchDog = watchDog(self.workdir)
        sock = self.sock
        self.update_queues = []
        for i in xrange(self.n_threads):
            self.update_queues.append(Queue())
            d = Process(target=self.worker, args=(i,))
            d.daemon=True
            d.start()
            self.process_list += [d]
            

        executed_testcases_old = 0
        while self.executed_testcases.value < n_testcases or n_testcases == 0:
            #wait for updates
            n = struct.unpack('<I',sock.recv(4))[0]
            d = ""
            while len(d) < n:
                d += sock.recv(n-len(d))
            update = json.loads(d)
            self.apply_update(update)
            for queue in self.update_queues:
                queue.put(update)
            if len(update["testcase_update"]) > 0:
                print "Got %d new Testcases %d Total; Coverage:" % (len(update["testcase_update"]), len(self.testcases)),
                for s in self.bitsets:
                    covered = bin(self.bitsets[s]).count("1")
                    missing = bin(~self.bitsets[s]).count("0")
                    print "%s: %d" % (s,covered),
                print "\n",

            #report
            report = {}
            report["testcase_report"] = []
            while self.testcase_report.qsize() > 0:
                t = self.testcase_report.get()
                report["testcase_report"].append(t)

            report["executed_testcases"] = self.executed_testcases.value - executed_testcases_old
            executed_testcases_old =  self.executed_testcases.value
                
            data = json.dumps(report)
            sock.sendall(struct.pack('<I',len(data)))
            sock.sendall(data)

    def apply_update(self, update):
        self.testcases += update["testcase_update"]

        for s,bitset in update["bitset_update"].iteritems():
            self.bitsets[s] = bitset

        self.crash_addr = update["crash_addr"]

    #execute testcases and process results
    def worker(self, worker_id):
        print "worker started"
        self.worker_id = worker_id
        while True:
            for mutated in self.get_testcases():
                self.execute_testcase(mutated)


    def execute_testcase(self, testcase):
        self.executed_testcases.value += 1
        try:
            stderr, crash, bitsets = self.callback(self, testcase)
            self.process_result( testcase, stderr, crash, bitsets)
        except:
            import traceback; traceback.print_exc()
            pass

    #detect new edges/crashes and appends to report queues
    def process_result(self, testcase, stderr, crash, bitsets):
        for s in bitsets:
            if s not in self.bitsets: self.bitsets[s] = 0

        testcase["bitsets"] = bitsets

        #detect new crash
        if crash and crash not in self.crash_addr:
            print "New crash %s" % crash
            testcase["crash"] = crash
            testcase["stderr"] = stderr
            self.testcase_report.put(testcase)


        if "minimize" not in testcase:
            #check for new edge
            new_blocks = 0
            blocks = 0
            for s in bitsets:
                bitset = int(bitsets[s])
                blocks += bin(bitset).count("1")
                new_blocks += bin((~self.bitsets[s]) & bitset).count("1")
                self.bitsets[s] |= bitset

            if new_blocks > 0:
                #remove unused mutations
                testcase["new_blocks"] = new_blocks
                minimize = {}
                minimize["i"] = 0
                minimize["reference"] = deepcopy(testcase)
                testcase["minimize"] = minimize
                self.work_queue.put(testcase)

        #remove unused mutations
        else:
            try:
                i = testcase["minimize"]["i"]
                reference = testcase["minimize"]["reference"]
            except:
                print testcase["minimize"]
                import os; os.kill(os.getpid(), 9)

            equal=True
            if not crash:
                for s in reference["bitsets"]:
                    if s not in bitsets or bitsets[s] != reference["bitsets"][s]:
                        equal = False
            else:
                equal = False

            #done
            if i >= len(testcase["mutators"]["data"]["mutations"]) - 1:

                if equal:
                    del testcase["minimize"]
                else:
                    if "minimize" in  reference: del reference["minimize"]
                    testcase = reference

                if "random-merge" not in testcase["description"] and len(testcase["mutators"]["data"]["mutations"]) > 0:
                    state = testcase["mutators"]["data"]["mutations"][-1]
                    testcase["description"] = ("offset=%d: " % state["offset"]) + state["description"] 
                print "Minimized testcase: New blocks: %d Parent: %d Description: %s " % (testcase["new_blocks"], testcase["id"], testcase["description"]),
                print "Mutations: %d" % len(testcase["mutators"]["data"]["mutations"])
                self.testcase_report.put(testcase)
                return

            #mutation was unused
            if equal:
                #print "%d unused" % i
                del testcase["minimize"]["reference"]
                testcase["minimize"]["reference"] = deepcopy(testcase)
                testcase["minimize"]["i"] = i

            else:
                #print "%d used" % i
                testcase["minimize"]["i"] = i+1

            testcase["mutators"]["data"]["mutations"] = reference["mutators"]["data"]["mutations"][:i] + reference["mutators"]["data"]["mutations"][i+1:]

            del testcase["bitsets"]
            self.work_queue.put(testcase)


    #genetic methods
    def get_testcases(self):
        while True:
            #apply updates
            try:
                update = self.update_queues[self.worker_id].get(False)
                self.apply_update(update)
            except:
                pass

            #initial and deterministic testcases
            try:
                testcase = self.work_queue.get(False)
                yield testcase
            except:
                pass

            #choose
            if len(self.testcases) == 0: continue
            s = reduce(lambda x,y: x+y["new_blocks"], self.testcases, 0)

            r = randrange(s)
            for t in sorted(self.testcases, key=lambda t: t["new_blocks"], reverse=True):
                r -= t["new_blocks"]
                if r < 0:
                    break
            tid = self.testcases.index(t)


            merged = self.random_merge(tid)
            if merged: yield merged

            #get
            testcase = self.testcases[tid]

            #mutate
            mutated = self.mutator.get_random_mutations( testcase ,maximum=8)
            mutated["parent_id"] = tid
            yield mutated

    #to mutator
    def random_merge(self, tid1):
        try:
            tid2 = randrange(len(self.testcases))
            if tid1 != tid2:
                mutated = deepcopy(self.testcases[tid1])
                name = choice(mutated["mutators"].keys())
                mutator1 = mutated["mutators"][name]
                mutator2 = self.testcases[tid2]["mutators"][name]
                l1 = randrange(len(mutator1["mutations"])) if len(mutator1["mutations"]) > 0 else 0
                l2 = randrange(len(mutator2["mutations"])) if len(mutator2["mutations"]) > 0 else 0
                mutator1["mutations"] = mutator1["mutations"][:l1] + mutator2["mutations"][:l2]
                mutated["mutators"][name] = mutator1
                mutated["description"] = "%s radnom merge %d-%d" % (name, tid1,tid2)
                mutated["parent_id"] = tid1
                return mutated
        except:
            #import traceback; traceback.print_exc()
            pass

    def stop(self):
        if self.watchDog:
            self.watchDog.exit()
            self.watchDog = None

        for p in self.process_list:
            print "killing", p
            p.terminate()
        self.process_list = []
        self.executed_testcases.value = 0


if __name__ == "__main__":
    import time
    if len(sys.argv) < 3:
        print "usage: %s ip port1 port2 ..." % sys.argv[0]
        sys.exit(1)

    #set up workers
    workdir = os.getcwd()
    workers = []
    for port in sys.argv[2:]:
        os.chdir(workdir)
        w = randomFuzzWorker(sys.argv[1],int(port), "teststuff/work/%d" % int(port))
        w.provision()
        workers += [w]

    try:
        while True:
            for i in xrange(len(workers)):
                print ">>> Working on worker %d <<<" % i
                workers[i].run(10000)
                workers[i].stop()
            
    except KeyboardInterrupt:
        import traceback; traceback.print_exc()
        for w in workers:
            w.stop()
        os.kill(os.getpid(), 9)
    except:
        import traceback; traceback.print_exc()
        for w in workers:
            w.stop()
        os.kill(os.getpid(), 9)
