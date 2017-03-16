#!/usr/bin/env python2
import os
import sys
import time
import socket
import json
import glob
from multiprocessing import Process,Queue,Value
from base64 import b64encode, b64decode
from threading import Thread
from Queue import PriorityQueue
from copy import deepcopy
from random import getrandbits, shuffle, choice, randrange
from shutil import copy2

from utils import *
from api import api

class master(api):
    def __init__(self, cfg, workdir, port):
        #misc
        self.rate = 0
        self.connections = []
        self._log = []
        self.report_queue = Queue()
        self.update_queue = Queue()
        self.workdir = workdir
        os.chdir(workdir)
        self.port = port
        self.connected_worker = Value('i', 0)

        #global config
        self.cmd = cfg["cmd"]
        self.env = cfg["env"]
        self.files = []
        self.crash_id = 0
        if os.path.exists("crash.json"):
            self.crash = load_json("crash.json")
        else:
            self.crash = []

        #fuzzing state
        self.testcases = []
        self.coverage = {}
        self.t0 = time.time()
        self.total_testcases = 0
        self.seed = ""

        #start threads
        self.log("fuzzer started")
        Thread(target=self.ui).start()

    def fuzz(self, seed):
        self.load_seed_state(seed)

        #this may consume much workload, so it is started as a new process
        self.p_process_preort = Process(target=self.process_report)
        self.p_process_preort.start()

        #wait for connections
        try:
            self.accept(self.port)
        except socket.error:
            import traceback; traceback.print_exc()
            pass

    def stop(self):
        self.log("stop")
        self.api_stop()
        self.report_queue.put({"exit": True})
        self.report_queue = Queue()
        self.update_queue = Queue()
        try:
            os.kill(self.p_process_preort.pid, 9)
        except:
            pass


    def load_seed_state(self, seed):
        self.seed = os.path.basename(seed)
        self.ext = seed.split(".")[-1]

        #seed state directory
        if not os.path.exists(self.seed):
            os.makedirs(self.seed)

        #load testcases
        self.testcases = []
        i = 0
        while os.path.exists("%s/testcase-%d.json" % (self.seed,i)):
            try:
                t = load_json("%s/testcase-%d.json" % (self.seed, i))
                self.testcases.append(t)
                i += 1
            except:
                break
        self.log("Loaded %d testcases for %s" % (len(self.testcases), self.seed))

        #load status
        if os.path.exists("%s/status.json" % self.seed):
            try:
                status = load_json("%s/status.json" % self.seed)
                self.t0 = time.time() - status["execution_time"]
                self.coverage = status["coverage"]
                self.total_testcases = status["total_testcases"]
            except:
                self.t0 = time.time()
                self.coverage = {}
                self.total_testcases
                
        else:
            self.t0 = time.time()
            self.coverage = {}
            self.total_testcases

        if len(self.testcases) > 0:
            for s in self.coverage:
                covered = bin(self.coverage[s]).count("1")
                missing = bin(~self.coverage[s]).count("0")
                self.log("%s: %d covered, %d missing, coverage: %.2f%%" % (s,covered,missing,100*covered/float(covered+missing)))

    def save_status(self):
        status = {}
        status["coverage"] = self.coverage
        status["execution_time"] = time.time() - self.t0
        status["total_testcases"] = self.total_testcases
        save_json("%s/status.json" % self.seed, status)


    def apply_update(self):
        try:
            testcase, coverage, crash, log = self.update_queue.get(False)
            self.testcases.append(testcase)
            self.coverage = coverage
            self.crash = crash
            for l in log:
                self.log(l)
        except:
            pass

    def process_report(self):
        print "update processor started"
        while True:
            testcase = self.report_queue.get()
            log = []

            if "total_testcases" in testcase:
                self.total_testcases = testcase["total_testcases"]
                self.save_status()
                continue

            if "exit" in testcase:
                break

            #update coverage if not crashed
            if "coverage" in testcase:
                coverage = testcase["coverage"]

                for s in coverage:
                    if s not in self.coverage: self.coverage[s] = 0
                new_blocks = 0
                blocks = 0
                for s in coverage:
                    bitset = int(coverage[s])
                    blocks += bin(bitset).count("1")
                    new_blocks += bin((~self.coverage[s]) & bitset).count("1")
                    self.coverage[s] |= bitset

            #append new testcase
            if new_blocks > 0:
                testcase["new_blocks"] = new_blocks
                testcase["blocks"] = blocks
                testcase["id"] = len(self.testcases)
                testcase["childs"] = []
                log.append("New Blocks: %d Parent: %d Description: %s" % (new_blocks, testcase["parent_id"], testcase["description"]))
                save_json("%s/testcase-%d.json" % (self.seed, len(self.testcases)),testcase)
                binary = b64decode(testcase["bin"])
                save_data("%s/testcase-%d.%s" % (self.seed, len(self.testcases), self.ext), binary)
                del testcase["bin"]
                self.testcases.append(testcase)

                pid = testcase["parent_id"]
                self.testcases[pid]["childs"] += [testcase["id"]]
                save_json("%s/testcase-%d.json" % (self.seed, pid),self.testcases[pid])
                self.save_status()

            #handle new crash
            new_crash = False
            if "crash" in testcase:
                crash = testcase["crash"]
                if crash not in self.crash:
                    log.append("New Crash @ %s !!" % (crash))
                    save_json("crash/crash-%d.json" % (len(self.crash)),testcase)
                    save_data("crash/crash-%d.stderr" % (len(self.crash)),testcase["stderr"])
                    new_crash = True

                    self.crash += [crash]
                    save_json("crash.json", self.crash)

            if new_blocks > 0 or new_crash:
                self.update_queue.put( (testcase, self.coverage, self.crash, log))
            
    
    #ui
    def ui(self):
        n_old = start = stop = 0
        log_old = ""
        while True:
            time.sleep(1)
            
            #determine testaces per second
            stop = time.time()
            alpha =  0.5
            n = self.total_testcases - n_old
            n_old = self.total_testcases
            self.rate = self.rate * alpha + (1-alpha) * n/(stop - start)
            start = stop

            #print stuff
            print "\x1b[0;0H"+"\x1b[2J"+"\r", 
            print "-=randomFuzz %s @ %d=-" % (self.seed, self.port)
            print "Testcases: %d" % (len(self.testcases))
            print "Rate: %.2f/s" % self.rate
            print "Total testcases: %d" % self.total_testcases
            print "Crash: %d" % len(self.crash)
            print "Worker: %d" % self.connected_worker.value
            print "Report Queue: %d" % self.report_queue.qsize()
            t = time.time() - self.t0
            print "Time: %dd:%dh:%dm:%ds" %((t/3600/24), (t/3600)%60, (t/60)%60, t%60)
            print "\nCoverage:"
            for s in self.coverage:
                covered = bin(self.coverage[s]).count("1")
                missing = bin(~self.coverage[s]).count("0")
                print "%s: %d covered, %d missing, coverage: %.2f%%" % (s,covered,missing,100*covered/float(covered+missing))

            print "\nLog:"
            for message in self._log[-16:]:
                print message
            t = time.time()
            print "%dd %02dh %02dm %02ds" %((t/3600/24)%365, (t/3600)%60, (t/60)%60, t%60)

            if log_old != self._log[-1]:
                last_event = time.time()
                log_old = self._log[-1]

            if time.time() - last_event > 100 and len(self.testcases) == 0:
                last_event = time.time()
                self.stop()

            if time.time() - last_event > 300:
                last_event = time.time()
                self.stop()

            self.apply_update()

    def log(self, msg):
        t = time.time() 
        timestamp =  "%dd %02dh %02dm %02ds" %((t/3600/24)%365, (t/3600)%60, (t/60)%60, t%60)
        self._log.append("%s %s" % (timestamp, msg))
        with open("log", "a") as f:
            f.write("%s %s\n" % (timestamp, msg))
            
