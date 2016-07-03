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
        self.tid = 0
        self.testcase_id = 0
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
        self.messages = [] #new testcase messages
        self.testcases_total = 0
        self.t0 = time.time()

        self.initial_testcase = dict()
        self.initial_testcase["id"] = self.tid
        self.initial_testcase["parent_id"] = 0
        self.initial_testcase["mutators"] = {}
        self.initial_testcase["description"] = ""

    #TODO mutations
    def add_mutator(self, name):
        mutator = {}
        mutator["mutations"] = []
        self.initial_testcase["mutators"][name] = mutator
        



    def launch(self):
        try:
            self.restore_state()
        except:
            pass
            import traceback; traceback.print_exc()

        self.initial_testcases.put(self.initial_testcase)
        #self.init_testcases()

        #start listener
        Thread(target=self.listener).start()

        try:
            self.run()
        except KeyboardInterrupt:
            import traceback; traceback.print_exc()
            os.kill(os.getpid(), 9)
        os.kill(os.getpid(), 9)


    def restore_state(self):
        return
        try:
            self.crash_addr = json.loads(open("crash_addr.json", "r").read())
        except:
            pass
        self.crash_id = len(self.crash_addr)

        self.bitsets = {}
        #restore testcases and queue
        testcases = json.loads(open("testcases.json", "r").read())
        for tid,testcase in testcases.iteritems():
            tid = int(tid)
            self.testcases[tid] = testcase
            self.work_queue.put(testcase)
            self.tid += 1

    def new_testcase(self, mutated, new_blocks):
        #add new testcase seed
        mutated["id"] = self.tid
        mutated["state"]["offset"] = -1
        mutated["prio"] = -1
        mutated["new_blocks"] = new_blocks
        
        self.testcases[self.tid] = mutated
        self.tid += 1

        with open("testcases.json", "w") as f:
            f.write(json.dumps(self.testcases))
        #with open("testcase-%d" % (mutated["id"]), "wb") as f:
        #    data = self.callback(self, mutated)
        #    f.write(data)

    def run(self):
        while True:
            time.sleep(1)

    #network
    def listener(self):
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

                update["crash_update"] = []

                s = json.dumps(update)
                conn.send(struct.pack('<I',len(s)))
                conn.send(s)

                #process updates
                n = struct.unpack('<I',conn.recv(4))[0]
                d = ""
                while len(d) < n:
                    d += conn.recv(n-len(d))
                report = json.loads(d)


                #process testcase update
                for testcase in report["testcase_report"]:
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
                        print "New Blocks: %d %s" % (new_blocks, testcase["description"])
                        testcase["new_blocks"] = new_blocks
                        testcase["blocks"] = blocks
                        testcase["id"] = len(self.testcases)
                        self.testcases.append(testcase)

                time.sleep(1)

        except:
            import traceback; traceback.print_exc()
            conn.close()
            return

    
    #ui
    def ui(self):
        n_old = start = stop = 0
        while True:
            sleep(1)
            #determine testaces per second
            stop = time()
            alpha =  0.5
            n = self.testcases_total - n_old
            n_old = self.testcases_total
            self.rate = self.rate * alpha + (1-alpha) * n/(stop - start)
            start = stop

            #print stuff
            print "\x1b[0;0H"+"\x1b[2J"+"\r", 
            print "-=randomFuzz=-"
            print "Testcase: %d (%d total)" % (self.testcase_id, self.tid)
            print "Rate: %.2f/s" % self.rate
            print "Total testcases: %d" % self.testcases_total
            print "Crash: %d" % len(self.crash_addr)
            print "Work Queue: %d" % (self.work_queue.qsize())
            t = time() - self.t0
            print "Time: %dd %dh %dm %ds" %((t/3600/24)%60, (t/3600)%60, (t/60)%60, t%60)
            print "\nCoverage:"
            for s in self.bitsets:
                covered = bin(self.bitsets[s]).count("1")
                missing = bin(~self.bitsets[s]).count("0")
                print "%s: %d covered, %d missing" % (s,covered,missing)

            print "\nLog:"
            for message in self.messages[-16:]:
                print message




if __name__ == "__main__":
    pass

