from random import randrange, choice
from binascii import hexlify, unhexlify
from copy import deepcopy
import struct
from seeds import seeds
#
class mutator(seeds):
    def __init__(self, seed):
        seeds.__init__(self, seed)

        self.mutations = []
        self.mutations.append( self.bitflip)
        self.mutations.append( self.byteflip)
        self.mutations.append( self.arith)
        self.mutations.append( self.arith_full)
        self.mutations.append( self.duplicate)
        self.mutations.append( self.delete)
        self.mutations.append( self.replace)
        self.mutations.append( self.insert)

        self.mutation_cache = {}


    def mutate_seed(self, mutator, data):
        mut = []
        for state in  mutator["mutations"]:
            m = state["mutation"]
            try:
                data = self.mutations[m](state, data=data)
                mut += [state]
            except:
                #import traceback; traceback.print_exc()
                pass
        mutator["len"] = len(data)
        mutator["mutations"] = mut
        return data

    def iterate(self, mutator, offset, init=True, init_mutations=2):
        if "state" not in mutator or mutator["state"]["offset"] != offset:
            mutator["state"] = {"tid": mutator["id"],"mutation": 0, "len":mutator["len"], "offset": offset}
            if not init:
                mutator["state"]["mutation"] = init_mutations
            
        m = mutator["state"]["mutation"]
        #print m, offset
        while m < len(self.mutations) and (init==False or m < init_mutations):
            n = self.mutations[m](mutator["state"])
            mutator["mutation"] = n
            if n is not None:
                mutated = deepcopy(mutator)
                mutated["mutations"] += [mutated["state"]]
                return n, mutated
            #print repr(self.mutations[m]) + " Done"
            m += 1
            mutator["state"] = {"tid": mutator["id"],"mutation": m, "len":mutator["len"], "offset": offset}
            mutator["state"]["mutation"] = m
        mutator["mutation"] = "done"
        return None, None

    def get_random_mutations(self, testcase, maximum=4):
        mutated = deepcopy(testcase)
        name = choice(mutated["mutators"].keys())
        mutator = mutated["mutators"][name]

        if len(self.mutation_cache) == 0:
            print "build cache"
            for m in xrange(len(self.mutations)):
                if m not in self.mutation_cache:
                    self.mutation_cache[m] = []
                mutator["state"] = {"mutation":m, "len":42, "offset":0}
                while True:
                    n = self.mutations[mutator["state"]["mutation"]](mutator["state"])
                    mutator["state"]["description"] = n
                    if n is None:
                        break
                    self.mutation_cache[m] += [deepcopy(mutator["state"])]
            del mutator["state"]

        description = ""
        for i in xrange(randrange(maximum)+1):
            m = randrange(len(self.mutations))
            state = deepcopy(choice(self.mutation_cache[m]))
            state["offset"] = randrange(max(1, mutator["len"]-4))
            mutator["mutations"] += [state]
            mutator["state"] = state
            mutator["description"] = state["description"]
            description += state["description"] + "; "

        mutated["mutators"][name] = mutator
        mutated["description"] = "%s: %s" % (name, description[:-2])
        for name2 in mutated["mutators"]:
            if name == name2:
                mutated["mutators"][name2]["altered"] = True
            else:
                mutated["mutators"][name2]["altered"] = False

        return mutated
                

    #     _        _             
    # ___| |_ _ __(_)_ __   __ _ 
    #/ __| __| '__| | '_ \ / _` |
    #\__ \ |_| |  | | | | | (_| |
    #|___/\__|_|  |_|_| |_|\__, |
    #                      |___/ 
    def bitflip(self, state, data=None):
        if "bitflip" not in state:
            state["bitflip"] = {"i":-1, "n": 1}
        i = state["bitflip"]["i"]
        n = state["bitflip"]["n"]
        offset = state["offset"]

        #mutate
        if data is not None:
            t = data
            mask = 0x00
            for j in xrange(n):
               mask |= 2**((i+n-1)%8) 
            t = t[:offset] + chr(ord(t[offset]) ^ mask) + t[offset+1:]
            return t

        #iterate
        if n > 4:
            return None
        i += 1
        if i+n-1 >= 8:
            i = 0
            n *= 2
        state["bitflip"]["i"] = i
        state["bitflip"]["n"] = n
        return "bitflip %d-%d" % (i,n)

    def byteflip(self, state, data=None):
        if "byteflip" not in state:
            state["byteflip"] = {"n": 1}
        n = state["byteflip"]["n"]
        offset = state["offset"]

        #mutate
        if data is not None:
            t = data
            f = ""
            for j in xrange(n):
                f += chr(ord(t[offset+j]) ^ 0xff)
            t = t[:offset] + f + t[offset+n:]
            return t

        #iterate
        n += 1
        if n > 4 or offset+n > state["len"]:
            return None

        state["byteflip"]["n"] = n
        return "byteflip %d" % n

    def arith(self, state, data=None):
        if "arith" not in state:
            state["arith"] = {"i":0}
        i = state["arith"]["i"]
        offset = state["offset"]

        #mutate
        if data is not None:
            t = data
            if i%2 == 0:
                t = t[:offset] + chr( (ord(t[offset]) + (i/2) )%256 ) + t[offset+1:]
            else:
                t = t[:offset] + chr( (ord(t[offset]) - (i/2) )%256 ) + t[offset+1:]
            return t

        #iterate
        if i > 32:
            return None
        state["arith"]["i"] = i + 1
        return "arith %d" % i

    def arith_full(self, state, data=None):
        if "arith-full" not in state:
            state["arith-full"] = {"i":0, "f":0}
        i = state["arith-full"]["i"]
        f = state["arith-full"]["f"]
        offset = state["offset"]

        formats = [
                    ("<I",0xffffffff, 4),
                    (">I",0xffffffff, 4),
                    ("<H",0xffff, 2),
                    (">H",0xffff, 2),
                    ("B",0xff, 1)
                    ]

        #mutate
        if data is not None:
            t = data
            tp, mask, l = formats[f]
            x = struct.unpack(tp, t[offset:offset+l])[0]
            
            if i < 32:#add
                x += (-1*(i%2)) * (i/2)
            elif i < 40:#mul
                if i % 2 == 0:
                    x *= ((i-32)/2)
                else:
                    x /= ((i-32)/2) + 2
            else: #shift
                if i % 2 == 0:
                    x = x << ((i-40)/2)
                else:
                    x = x >> ((i-40)/2)

            t = t[:offset] + struct.pack(tp, x & mask) + t[offset+l:]
            return t

        #iterate
        if i > 56:
            state["arith-full"]["f"] = f + 1
            i = -1

        if f >= len(formats):
            return None
        state["arith-full"]["i"] = i + 1
        return "arith-full %d,%d" % (f,i)

    def duplicate(self, state, data=None):
        if "duplicate" not in state:
            state["duplicate"] = {"i":0, "n":2}
        i = state["duplicate"]["i"]
        n = state["duplicate"]["n"]
        offset = state["offset"]

        #mutate
        if data is not None:
            t = data
            if i % 2 == 0:
                t = t[:offset] + (t[offset:offset+i]*(n/2+1)) + t[offset:]
            else:
                t = t[:offset] + (t[offset:offset+i]*(n/2+1)) + t[offset+i*(n/2+1):]
            return t

        #iterate
        if i > 64 or offset+i >= state["len"]:
            n += 1
            i = 0
        if n > 8:
            return None
        state["duplicate"]["i"] = i + 1
        state["duplicate"]["n"] = n
        return "duplicate %d,%d" % (i,n)

    def delete(self, state, data=None):
        if "delete" not in state:
            state["delete"] = {"i":0}
        i = state["delete"]["i"]
        offset = state["offset"]

        #mutate
        if data is not None:
            t = data
            t = t[:offset] + t[offset+i:]
            return t

        #iterate
        if i > 64 or offset+i >= state["len"]:
            return None
        state["delete"]["i"] = i + 1
        return "delete %d" % i

    def replace(self, state, data=None):
        if "replace" not in state:
            state["replace"] = {"i":0}
        i = state["replace"]["i"]
        offset = state["offset"]

        #mutate
        if data is not None:
            t = data
            s = self.seeds[i]
            t = t[:offset] + str(s) + t[offset+len(s):]
            return t

        #iterate
        if i+1 >= len(self.seeds):
            return None
        state["replace"]["i"] = i + 1
        return "replace %s" % hexlify(self.seeds[i][:8])

    def insert(self, state, data=None):
        if "insert" not in state:
            state["insert"] = {"i":0}
        i = state["insert"]["i"]
        offset = state["offset"]

        #mutate
        if data is not None:
            t = data
            s = self.seeds[i]
            t = t[:offset] + str(s) + t[offset:]
            return t

        if i+1 >= len(self.seeds):
            return None
        state["insert"]["i"] = i + 1
        return "insert %s" % hexlify(self.seeds[i][:8])

    
if __name__ == "__main__":
    m = mutator([])
    seed = "\x00"* 128
    testcase = {"len": 128, "id": 0, "mutations": []}

    mut = m.get_random_mutations(testcase)
    print hexlify( m.mutate_seed(mut, seed))
    print mut
