#!/usr/bin/env python
import sys
from scapy.all import *
import os
import json
import re
from mutator import *


m = mutator([])
def process(pack):
        global m
        for i in xrange(10):
            mutated,mpack = m.mutate_random(str(pack))
            if len(mpack) <= 14:
                continue
            for state in mutated["mutations"]:
                print state["description"],"; ",
            print ""

            #fix checksums
            mpack = hdr = RadioTap(mpack)
            while hdr.payload:
                if hasattr(hdr, "chksum"):
                    del hdr.chksum
                hdr = hdr.payload

            try:
                sendp(mpack, iface=sys.argv[1], verbose=False)
            except:
                pass


if __name__ == "__main__":
    if os.getuid() != 0:
        print "this has to be run as root!"
        sys.exit(-1)

    while True:
        try:
            sniff(prn=process, iface=sys.argv[1], count=10)
        except:
            pass
