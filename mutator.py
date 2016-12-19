from random import randrange, choice
from binascii import hexlify, unhexlify
from copy import deepcopy
import struct
from seeds import seeds
#
class mutator(seeds):
    def __init__(self, seed):
        seeds.__init__(self, seed)

        self.formats = [
            ("<I",0xffffffff, 4),
            (">I",0xffffffff, 4),
            ("<H",0xffff, 2),
            (">H",0xffff, 2),
            ("B",0xff, 1)
            ]

        self.mutations = []
        self.mutations.append( self.bitflip)
        self.mutations.append( self.byteflip)
        self.mutations.append( self.arith)
        self.mutations.append( self.arith_full)
        self.mutations.append( self.duplicate)
        self.mutations.append( self.delete)
        self.mutations.append( self.replace)
        self.mutations.append( self.insert)
        self.mutations.append( self.insert_add)

    def mutate_seed(self, mutator, data):
        mut = []
        for state in  mutator["mutations"]:
            m = state["mutation"]
            try:
                data = self.mutations[m](state=state, data=data)
                mut += [state]
                mutator["description"] = state["description"]
            except:
                #import traceback; traceback.print_exc()
                pass

        mutator["len"] = len(data)
        mutator["mutations"] = mut
        return data

    def get_random_mutations(self, testcase, maximum=4, mutations=None, start=0, stop=0):
        mutated = deepcopy(testcase)
        name = choice(mutated["mutators"].keys())
        mutator = mutated["mutators"][name]

        description = ""
        for i in xrange(randrange(maximum)+1):
            if not mutations:
                m = randrange(len(self.mutations))
            else:
                m = choice(mutations)

            state = self.mutations[m](state=None, data=None)
            state["mutation"] = m

            if stop-start <= 0:
                state["offset"] = randrange(max(1, mutator["len"]-4))
            else:
                state["offset"] = randrange(start, stop)

            mutator["mutations"] += [state]
            description += ("offset=%d: " % state["offset"]) + state["description"] + "; "

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
    def bitflip(self, state=None, data=None):
        #rand
        if state is None:
            state = {"bitflip": {}}
            i = state["bitflip"]["i"] = randrange(4) + 1
            n = state["bitflip"]["n"] = randrange(8)
            state["description"] = "bitflip %d-%d" % (i,n)
            return state

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

    def byteflip(self, state=None, data=None):
        #rand
        if state is None:
            state = {"byteflip": {}}
            n = state["byteflip"]["n"] = randrange(4)
            state["description"] = "byteflip %d" % n
            return state

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


    def arith(self, state=None, data=None):
        if state is None:
            state = {"arith": {}}
            i = state["arith"]["i"] = randrange(32)+1
            state["description"] = "arith %d" % i
            return state

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


    def arith_full(self, state=None, data=None):
        if state is None:
            state = {"arith-full": {}}
            i = state["arith-full"]["i"] = randrange(56)
            f = state["arith-full"]["f"] = randrange(len(self.formats))
            state["description"] = "arith-full %s,%d" % (self.formats[f][0],i)

            return state

        i = state["arith-full"]["i"]
        f = state["arith-full"]["f"]
        offset = state["offset"]

        #mutate
        if data is not None:
            t = data
            tp, mask, l = self.formats[f]
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

    def duplicate(self, state=None, data=None):
        if state is None:
            state = {"duplicate": {}}
            i = state["duplicate"]["i"] = randrange(64)
            n = state["duplicate"]["n"] = randrange(8)
            state["description"] = "duplicate %d,%d" % (i,n)
            return state
            
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


    def delete(self, state=None, data=None):
        if state is None:
            state = {"delete": {}}
            i = state["delete"]["i"] = randrange(64)
            state["description"] = "delete %d" % i
            return state

        i = state["delete"]["i"]
        offset = state["offset"]

        #mutate
        if data is not None:
            t = data
            t = t[:offset] + t[offset+i:]
            return t

    def replace(self, state=None, data=None):
        if state is None:
            state = {"replace": {}}
            i = state["replace"]["i"] = randrange(len(self.seeds))
            state["description"] = "replace %s" % hexlify(self.seeds[i][:8])
            return state

        i = state["replace"]["i"]
        offset = state["offset"]

        #mutate
        if data is not None:
            t = data
            s = self.seeds[i]
            t = t[:offset] + str(s) + t[offset+len(s):]
            return t

    def insert(self, state=None, data=None):
        if state is None:
            state = {"insert": {}}
            i = state["insert"]["i"] = randrange(len(self.seeds))
            state["description"] = "insert %s" % hexlify(self.seeds[i][:8])
            return state
    

        i = state["insert"]["i"]
        offset = state["offset"]

        #mutate
        if data is not None:
            t = data
            s = self.seeds[i]
            t = t[:offset] + str(s) + t[offset:]
            return t

    def insert_add(self, state=None, data=None):
        if state is None:
            state = {"insert-add": {}}
            i = state["insert-add"]["i"] = randrange(len(self.seeds))
            f = state["insert-add"]["f"] = randrange(len(self.formats))
            off = state["insert-add"]["off"] = randrange(64)
            j = state["insert-add"]["j"] = randrange(3) - 1
            state["description"] = "insert_add %s-%d" % ( hexlify(self.seeds[i][:8]), off)
            return state
    
        i = state["insert-add"]["i"]
        f = state["insert-add"]["f"]
        off = state["insert-add"]["off"]
        j = state["insert-add"]["j"]
        offset = state["offset"]

        #mutate
        if data is not None:
            t = data
            s = self.seeds[i]
            t = t[:offset] + str(s) + t[offset:]

            tp, mask, l = self.formats[f]
            x = struct.unpack(tp, t[offset-off:offset+l-off])[0]
            x += len(s) + j
            t = t[:offset-off] + struct.pack(tp, x & mask) + t[offset+l-off:]
            return t

if __name__ == "__main__":
    m = mutator([])
    seed = "\x00"* 128
    testcase = {"len": 128, "id": 0, "mutations": []}

    mut = m.get_random_mutations(testcase)
    print hexlify( m.mutate_seed(mut, seed))
    print mut
