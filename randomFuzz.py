#!/usr/bin/env python2
import os
import pickle
import sys
from multiprocessing import Process,Queue
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
import glob
from utils import *
from mutator import mutator



class randomFuzz:
    def __init__(self, files, workdir, seeds, callback, port=1337):
        #fuzzing state
        self.testcases = []
        self.callback = callback
        self.watchDog = watchDog()
        self.mutator = mutator(seeds)

        self.seeds = seeds
        self.port = port
        self.bitsets = {}
        self.initial_testcases = Queue()

        #copy file to workdir
        self.files = []
        for fname in files:
            copy2(fname, workdir)
            os.chmod(fname, 0700)
            self.files.append(os.path.basename(fname))
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

        try:
            self.accept()
        except KeyboardInterrupt:
            import traceback; traceback.print_exc()
            os.kill(os.getpid(), 9)
        os.kill(os.getpid(), 9)


    def restore_state(self):
        try:
            testcases = load_json("testcases.json")
            self.log("Loaded %d testcases" % len(testcases))
            for testcase in testcases:
                self.initial_testcases.put(testcase)
            self.crash_addr = load_json("crash_addr.json")
        except:
            pass


    #network
    def accept(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", self.port))
        s.listen(1)
        s.setblocking(1)
        while True:
            conn, addr = s.accept()
            Thread(target=self.connection_handler, args=(conn,)).start()

    def connection_handler(self, conn):
        print "worker connected"
        provision = {}
        provision["seeds"] = self.seeds
        provision["testcases"] = self.testcases
        provision["crash_addr"] = self.crash_addr
        provision["callback"] = b64encode(cloud.serialization.cloudpickle.dumps(self.callback))

        provision["initial_testcases"] = []
        while self.initial_testcases.qsize() > 0:
            testcase = self.initial_testcases.get()
            provision["initial_testcases"].append(testcase)

        provision["files"] = {}
        for fname in self.files:
            data = open(fname,"rb").read()
            fname = fname.split("/")[-1]
            provision["files"][fname] = b64encode(data)

        s = json.dumps(provision)
        last_tid = len(self.testcases)
        conn.send(struct.pack('<I',len(s)))
        conn.send(s)
        del provision
        del s
        print "worker provisioned"

        try:
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

                #process testcase update
                for testcase in report["testcase_report"] + report["crash_report"]:
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
                        self.log("New Blocks: %d Description: %s" % (new_blocks, testcase["description"]))
                        save_json("testcases.json", self.testcases)
                        save_json("testcase-%d.json" % (len(self.testcases)),testcase)
                        self.testcases.append(testcase)

                for testcase in report["crash_report"]:
                    crash = testcase["crash"]
                    if crash not in self.crash_addr:
                        self.log("New Crash @ %s !!" % (crash))
                        save_json("crash_addr.json", self.crash_addr)
                        save_json("crash-%d.json" % (len(self.crash_addr)),testcase)
                        save_data("crash-%d.stderr" % (len(self.crash_addr)),testcase["stderr"])

                        self.crash_addr += [crash]

                time.sleep(1)

        except:
            import traceback; traceback.print_exc()
            conn.close()
            return
    
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
            print "-=randomFuzz=-"
            print "Testcases: %d" % (len(self.testcases))
            print "Rate: %.2f/s" % self.rate
            print "Total testcases: %d" % self.total_testcases
            print "Crash: %d" % len(self.crash_addr)
            t = time.time() - self.t0
            print "Time: %dd %dh %dm %ds" %((t/3600/24)%60, (t/3600)%60, (t/60)%60, t%60)
            print "\nCoverage:"
            for s in self.bitsets:
                covered = bin(self.bitsets[s]).count("1")
                missing = bin(~self.bitsets[s]).count("0")
                print "%s: %d covered, %d missing" % (s,covered,missing)

            print "\nLog:"
            for message in self._log[-16:]:
                print message
            print time.strftime("%H:%M:%S", time.gmtime())

    def log(self, msg):
        self._log.append("%s %s" % (time.strftime("%H:%M:%S", time.gmtime()), msg))
            




if __name__ == "__main__":
    pass

