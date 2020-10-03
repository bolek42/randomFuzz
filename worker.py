#!/usr/bin/env python2
import sys
import socket
import os
import json
from multiprocessing import Process,Queue,cpu_count,Value
from base64 import b64encode, b64decode
from random import getrandbits, randrange, choice, shuffle
from subprocess import Popen, PIPE, STDOUT
from copy import deepcopy
from shutil import copy2

from mutators.mutator import mutator
from utils import *
from api import api


class worker(api):
    def __init__(self, workdir, n_threads=0):
        self.n_threads = cpu_count() if n_threads == 0 else n_threads
        self.process_list = []
        self.workdir = workdir

        self.work_queue = Queue()
        self.update_queues = []
        self.testcase_report = Queue()

        self.coverage = dict()
        self.testcases = []
        self.executed_testcases = Value('i', 0)

        self.mutator = mutator()

        if not os.path.exists(workdir):
            os.makedirs(workdir)
        os.chdir(workdir)

    def run(self, n_testcases=0):
        #cleanup workdir
        for fname in glob.glob("*sancov") + glob.glob("t-*"):
            os.remove(fname)

        self.work_queue.put(self.mutator.initial_testcase())
        self.executor = executor(self.cmd, ".")

        #start worker threads
        self.update_queues = []
        for i in xrange(self.n_threads):
            self.update_queues.append(Queue())
            d = Process(target=self.worker, args=(i,))
            d.daemon=True
            d.start()
            self.process_list += [d]

        self.client(n_testcases)

    def apply_update(self, update):
        if len(update["testcase_update"]) > 0:
            for t in update["testcase_update"]:
                pid = t["parent_id"]
                self.testcases += [t]
                if t["id"] > 0 and t["id"] < len(self.testcases):
                    self.testcases[pid]["childs"] += [t["id"]]

            self.mutator.random_merge_cache = {}

        if "coverage_update" in update:
            for k in update["coverage_update"].keys():
                if k not in self.coverage:
                    self.coverage[k] = set()
                self.coverage[k].update(set(update["coverage_update"][k]))

        self.crash = update["crash"]

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
            data = self.mutator.mutate_seed(testcase, self.seed_data)
            stderr, crash, coverage = self.executor.call(data, self.ext)
            if len(coverage) > 0:
                self.process_result(testcase, stderr, crash, coverage, data)
        except:
            import traceback; traceback.print_exc()
            pass


    #detect new edges/crashes and appends to report queues
    def process_result(self, testcase, stderr, crash, coverage, binary):
        testcase["coverage"] = (coverage)
        testcase["bin"] = b64encode(binary)

        #detect new crash
        if crash and crash not in self.crash:
            print "New crash %s" % crash
            testcase["crash"] = crash
            testcase["stderr"] = stderr
            self.testcase_report.put(testcase)
            return


        #found new blocks, requeue to remove unused mutations
        if "minimize" not in testcase:
            new_blocks = self.compute_new_blocks(coverage)

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
            i = testcase["minimize"]["i"]
            reference = testcase["minimize"]["reference"]

            #test if testcase covered equal or more blocks
            ge = False
            if not crash: 
                new_blocks = self.compute_new_blocks(coverage)

                testcase["new_blocks"] = new_blocks
                if new_blocks >= reference["new_blocks"]:
                    ge = True

            #done
            if i >= len(testcase["mutations"]) - 1:
                if not ge:
                    testcase = reference

                if "minimize" in  testcase: del testcase["minimize"]

                if "random-merge" not in testcase["description"] and len(testcase["mutations"]) > 0:
                    state = testcase["mutations"][-1]
                    testcase["description"] = ("offset=%d: " % state["offset"]) + state["description"] 

                print "Minimized testcase: New blocks: %d Parent: %d Description: %s " % (testcase["new_blocks"], testcase["id"], testcase["description"]),
                print "Mutations: %d" % len(testcase["mutations"]), 
                print "Report Queue: %d" % self.testcase_report.qsize()
                new_blocks = self.compute_new_blocks(coverage)
                self.testcase_report.put(testcase)
                return


            #mutation was unused
            if ge:
                #print "%d unused" % i
                del testcase["minimize"]["reference"]
                testcase["minimize"]["reference"] = deepcopy(testcase)
                testcase["minimize"]["i"] = i

            else:
                #print "%d used" % i
                testcase["minimize"]["i"] = i+1

            testcase["mutations"] = reference["mutations"][:i] + reference["mutations"][i+1:]

            del testcase["coverage"]
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
                while True:
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

            merged = self.mutator.random_merge(self.testcases, tid)
            if merged: yield merged

            #get
            testcase = self.testcases[tid]

            #mutate
            if tid == 0:
                mutated = self.mutator.random_mutation(testcase ,maximum=8)
            else:
                mutated = self.mutator.random_mutation(testcase ,maximum=8)
            mutated["parent_id"] = tid
            yield mutated

    def stop(self):
        try:
            self.executor.watchDog.exit()
        except:
            pass
        for p in self.process_list:
            print "killing", p.pid
            os.kill(p.pid,9)
        self.process_list = []
        self.executed_testcases.value = 0



    def crash_fuzz( self, files):
        self.addrs = []
        self.crashes = []

        for fname in files:
            with open(fname, "r") as f:
                testcase = json.loads(f.read())
                testcase["description"] = ""

            stderr, crash, coverage = self.callback(self, testcase)
            self.crash_fuzz_process_crash(stderr, testcase)

        #fuzz crash
        while True:
            testcase = choice(self.crashes)
            mutated = deepcopy(testcase)
            mutated["mutators"]["data"] = self.mutator.get_random_mutations(testcase["mutators"]["data"] , maximum=1)#, mutations=[3]) ##, start=711-16, stop=711+16)
            mutated["mutators"]["data"] = self.mutator.get_random_mutations(testcase["mutators"]["data"] , maximum=1, mutations=[3], start=0, stop=0)
            stderr, crash, coverage = self.callback(self, mutated)
            self.crash_fuzz_process_crash(stderr, mutated)

    def crash_fuzz_process_crash(self, stderr, testcase):
        for line in stderr.split("\n"):
            if "ERROR: AddressSanitizer:" in line: 
                try:
                    addr = re.findall("on [a-z ]*address 0x[0-9a-f]*", line)[0]
                    addr = re.findall("0x[0-9a-f]*", addr)[0]
                    crash = re.findall("pc 0x[0-9a-f]*", line)[0]
                    addr = "%s-%s" % (crash,addr)
                    if addr not in self.addrs:
                        if "READ" in stderr:
                            cause = "READ"
                        elif "WRITE" in stderr:
                            cause = "WRITE"
                        else:
                            cause = "OTHER"

                        stderr, crash, coverage = self.callback(self, testcase, dumpfile="crashFuzz-%s-%s.bin" % (addr,cause))
                        save_data("crashFuzz-%s-%s.stderr" % (addr, cause), stderr)
                        print cause, addr, testcase["description"]
                        self.addrs += [addr]
                        self.crashes += [testcase]
                except:
                    #print stderr
                    import traceback; traceback.print_exc()
            i += 1

