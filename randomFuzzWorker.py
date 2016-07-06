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


class randomFuzzWorker():
    def __init__(self, ip, port, workdir, n_threads=0):
        os.environ["ASAN_OPTIONS"]="coverage=1:coverage_bitset=1"
        os.environ["MALLOC_CHECK_"]="0"
        os.environ["LD_LIBRARY_PATH"]="."

        self.ip = ip
        self.port = port
        self.workdir = workdir

        self.bitsets = {}
        self.testcases = []
        self.active = []
        self.executed_testcases = Value('i', 0)

        self.watchDog = watchDog()
        self.work_queue = Queue()
        self.testcase_count = Queue()
        self.update_queues = []

        self.testcase_report = Queue()

        self.provision()
        self.run()


    def provision(self):
        print "connecting"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 10*1024*1024)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 10*1024*1024)
        s.settimeout(100)
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
        self.testcases += provision["testcases"]
        self.bitsets = provision["bitsets"]
        self.crash_addr = provision["crash_addr"]
        self.active = provision["active"]
        self.mutator = mutator(provision["seeds"])
        self.callback = pickle.loads(b64decode(provision["callback"]))

        #write Files to Disk
        for fname in provision["files"]:
            copy2(fname, self.workdir)
            os.chmod(fname, 0700)

        os.chdir(self.workdir)

        #fetch initial testcases
        print "Got %d initial testcases" % len(provision["initial_testcases"])
        for testcase in provision["initial_testcases"]:
            self.work_queue.put(testcase)

        #cleanup
        del provision
        print "privision done"

    def run(self):
        #start worker
        sock = self.sock
        for i in xrange(cpu_count() if n_threads == 0 else n_threads):
            self.update_queues.append(Queue())
            d = Process(target=self.worker, args=(i,))
            d.daemon=True
            d.start()
            

        while True:
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
            while self.testcase_report.qsize() > 0 and len(report["testcase_report"]) < 10:
                t = self.testcase_report.get()
                report["testcase_report"].append(t)

            report["executed_testcases"] = self.executed_testcases.value
            self.executed_testcases.value = 0
                
            data = json.dumps(report)
            sock.send(struct.pack('<I',len(data)))
            sock.send(data)

    def apply_update(self, update):
        self.testcases += update["testcase_update"]

        for s,bitset in update["bitset_update"].iteritems():
            self.bitsets[s] = bitset

        self.crash_addr = update["crash_addr"]
        self.active = update["active"]

    #execute testcases and process results
    def worker(self, worker_id):
        print "worker started"
        while True:

            #initial and deterministic testcases
            while self.work_queue.qsize() > 0:
                    testcase = self.work_queue.get()
                    self.execute_testcase(testcase)
                    pass

            #randomly mutate testcases
            for mutated in self.get_testcases():
                #apply updates
                if self.update_queues[worker_id].qsize() > 0:
                    update = self.update_queues[worker_id].get()
                    self.apply_update(update)

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

        #check for new edge
        new_blocks = 0
        blocks = 0
        for s in bitsets:
            bitset = int(bitsets[s])
            blocks += bin(bitset).count("1")
            new_blocks += bin((~self.bitsets[s]) & bitset).count("1")
            self.bitsets[s] |= bitset

        testcase["bitsets"] = bitsets

        if new_blocks > 0:
            print "New blocks: %d, tid: %d Description: %s" % (new_blocks, testcase["id"], testcase["description"])
            self.testcase_report.put(testcase)

        #detect new crash
        if crash and crash not in self.crash_addr:
            print "New crash %s" % crash
            testcase["crash"] = crash
            testcase["stderr"] = stderr
            self.testcase_report.put(testcase)

    #genetic methods
    def get_testcases(self):
        for tid in xrange(len(self.testcases)):
            if tid not in self.active:
                continue

            merged = self.random_merge(tid)
            if merged:
                yield merged
            #get
            testcase = self.testcases[tid]

            #mutate
            mutated = self.mutator.get_random_mutations( testcase ,maximum=4)
            mutated["parent_id"] = tid
            yield mutated

    #to mutator
    def random_merge(self, tid1):
        try:
            tid2 = choice(self.active)
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


if __name__ == "__main__":
    import time
    if len(sys.argv) == 4:
        n_threads = int(sys.argv[3])
    else:
        n_threads = 0

    while True:
        try:
            randomFuzzWorker(sys.argv[1],int(sys.argv[2]), "teststuff/work", n_threads)
            time.sleep(1)
        except KeyboardInterrupt:
            import traceback; traceback.print_exc()
            os.kill(os.getpid(), 9)
        except:
            import traceback; traceback.print_exc()
            os.kill(os.getpid(), 9)
t
