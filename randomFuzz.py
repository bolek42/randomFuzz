#!/usr/bin/env python2
import os
import pickle
import sys
from multiprocessing import Process,Queue,Value
from random import getrandbits, shuffle, choice, randrange
import time
import socket
import json
from base64 import b64encode, b64decode
from threading import Thread
from copy import deepcopy
import zlib
import struct
import cloud
import md5
import re
from Queue import PriorityQueue
import socket
import json
from base64 import b64encode, b64decode
import struct
import cloud
from shutil import copy2
from utils import *
from mutator import mutator

class randomFuzz:
    def __init__(self, files, seed, workdir, seeds, callback, port=1337):
        #fuzzing state
        self.testcases = []
        self.callback = callback
        self.watchDog = watchDog(workdir)
        self.mutator = mutator(seeds)
        self.workdir = workdir
        self.seed = seed
        self.connected_worker = Value('i', 0)

        self.seeds = seeds
        self.port = port
        self.bitsets = {}
        self.initial_testcases = Queue()
        self.report_queue = Queue()
        self.update_queue = Queue()

        #create workdir
        if not os.path.exists(workdir):
            os.makedirs(workdir)

        #copy file to workdir
        self.files = []
        for fname in files:
            copy2(fname, workdir)
            os.chmod(fname, 0700)
            self.files.append(fname)
        os.chdir(workdir)

        self.crash_addr = [] #addresses of crashes
        self.crash_id = 0

        self.rate = 0 #testcases per second
        self._log = [] #new testcase messages
        self.total_testcases = 0
        self.t0 = time.time()

        self.initial_testcase = dict()
        self.initial_testcase["id"] = 0
        self.initial_testcase["parent_id"] = 0
        self.initial_testcase["mutators"] = {}
        self.initial_testcase["description"] = ""

    #TODO mutations
    def add_mutator(self, name, length=42):
        mutator = {}
        mutator["mutations"] = []
        mutator["len"] = length #XXX dirty fix for missing length
        self.initial_testcase["mutators"][name] = mutator
        
    def launch(self):
        self.initial_testcases.put(self.initial_testcase)
        try:
            self.restore_state()
            pass
        except:
            pass
            import traceback; traceback.print_exc()

        #start listener
        Thread(target=self.ui).start()
        Thread(target=self.apply_update).start()
        Process(target=self.process_report).start()

        try:
            self.accept()
        except KeyboardInterrupt:
            import traceback; traceback.print_exc()
            os.kill(os.getpid(), 9)
        os.kill(os.getpid(), 9)


    def restore_state(self):
        try:
            self.testcases = []
            i = 0
            while True:
                try:
                    t = load_json("testcase-%d.json" % i)
                    self.testcases.append(t)
                    i += 1
                except:
                    break
            self.log("Loaded %d testcases" % len(self.testcases))
            self.bitsets = load_json("bitsets.json")
            self.crash_addr = load_json("crash_addr.json")
        except:
            pass

    #network
    def accept(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(100000)
        s.bind(("0.0.0.0", self.port))
        s.listen(1)
        s.setblocking(1)
        while True:
            conn, addr = s.accept()
            Thread(target=self.connection_handler, args=(conn,)).start()

    def connection_handler(self, conn):
        print "worker connected"
        self.connected_worker.value += 1
        provision = {}
        provision["seed"] = self.seed
        provision["seeds"] = self.seeds
        provision["testcases"] = self.testcases
        provision["bitsets"] = self.bitsets
        provision["crash_addr"] = self.crash_addr
        provision["callback"] = b64encode(cloud.serialization.cloudpickle.dumps(self.callback))

        provision["initial_testcases"] = []
        while self.initial_testcases.qsize() > 0:
            testcase = self.initial_testcases.get()
            provision["initial_testcases"].append(testcase)

        provision["files"] = []
        for fname in self.files:
            provision["files"].append(fname)

        try:
            s = json.dumps(provision)
            last_tid = len(self.testcases)
            conn.sendall(struct.pack('<I',len(s)))
            conn.sendall(s)
            del provision
            del s
            print "worker provisioned"

            while True:
                #send update
                update = {}
                update["testcase_update"] = self.testcases[last_tid:]
                last_tid = len(self.testcases)

                update["bitset_update"] = {}
                if len(update["testcase_update"]) > 0:
                    update["bitset_update"] = self.bitsets

                update["crash_addr"] = self.crash_addr

                s = json.dumps(update)
                conn.send(struct.pack('<I',len(s)))
                conn.send(s)

                #process updates
                n = struct.unpack('<I',conn.recv(4))[0]
                d = ""
                while len(d) < n:
                    d += conn.recv(n-len(d))
                report = json.loads(d)
                self.total_testcases += report["executed_testcases"]

                for testcase in report["testcase_report"]:
                    self.report_queue.put(testcase)

                time.sleep(1)

        except:
            import traceback; traceback.print_exc()
            conn.close()
            self.connected_worker.value -= 1
            return

    def apply_update(self):
        while True:
            testcase, bitsets, crash_addr, log = self.update_queue.get()
            self.testcases.append(testcase)
            self.bitsets = bitsets
            self.crash_addr = crash_addr
            for l in log:
                self.log(l)

    def process_report(self):
        print "update processor started"
        while True:
            testcase = self.report_queue.get()
            log = []

            #update bitsets if not crashed
            if "bitsets" in testcase:
                bitsets = testcase["bitsets"]

                for s in bitsets:
                    if s not in self.bitsets: self.bitsets[s] = 0
                new_blocks = 0
                blocks = 0
                for s in bitsets:
                    bitset = int(bitsets[s])
                    blocks += bin(bitset).count("1")
                    new_blocks += bin((~self.bitsets[s]) & bitset).count("1")
                    self.bitsets[s] |= bitset

                if new_blocks > 0:
                    testcase["new_blocks"] = new_blocks
                    testcase["blocks"] = blocks
                    testcase["id"] = len(self.testcases)
                    log.append("New Blocks: %d Description: %s" % (new_blocks, testcase["description"]))
                    save_json("testcase-%d.json" % (len(self.testcases)),testcase)
                    self.testcases.append(testcase)
                    save_json("bitsets.json", self.bitsets)

            #handle new crash
            new_crash = False
            if "crash" in testcase:
                crash = testcase["crash"]
                crash = re.findall("0x[0-9a-f]*", crash)[0]
                if crash not in self.crash_addr:
                    new_crash = True
                    log.append("New Crash @ %s !!" % (crash))
                    save_json("crash-%d.json" % (len(self.crash_addr)),testcase)
                    save_data("crash-%d.stderr" % (len(self.crash_addr)),testcase["stderr"])
                    self.callback(self, testcase, dumpfile="crash-%d.bin" % len(self.crash_addr), execute=False)

                    #notify
                    cmd = "(echo \"Subject: Crash for %s @ %s!!\" ; cat crash-%d.stderr) | msmtp  dabolek42@gmail.com" % (os.path.basename(self.seed), crash, len(self.crash_addr))
                    os.system(cmd)

                    self.crash_addr += [crash]
                    save_json("crash_addr.json", self.crash_addr)

            if new_blocks > 0 or new_crash:
                self.update_queue.put( (testcase, self.bitsets, self.crash_addr, log))
            
    
    #ui
    def ui(self):
        n_old = start = stop = 0
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
            print "Crash: %d" % len(self.crash_addr)
            print "Worker: %d" % self.connected_worker.value
            print "Report Queue: %d" % self.report_queue.qsize()
            t = time.time() - self.t0
            print "Time: %dd %dh %dm %ds" %((t/3600/24)%60, (t/3600)%60, (t/60)%60, t%60)
            print "\nCoverage:"
            for s in self.bitsets:
                covered = bin(self.bitsets[s]).count("1")
                missing = bin(~self.bitsets[s]).count("0")
                print "%s: %d covered, %d missing, coverage: %.2f%%" % (s,covered,missing,100*covered/float(covered+missing))

            print "\nLog:"
            for message in self._log[-16:]:
                print message
            print time.strftime("%H:%M:%S", time.gmtime())

    def log(self, msg):
        self._log.append("%s %s" % (time.strftime("%H:%M:%S", time.gmtime()), msg))
            

if __name__ == "__main__":
    pass

