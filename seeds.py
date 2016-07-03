import struct


class seeds:
    def __init__(self, seed):

        self.seeds = self.seeds_string()
        self.seeds += seed

        self.seeds_32 = self.seed_int32()
        for i in self.seeds_32:
            self.seeds += [struct.pack('<I',i)]
            self.seeds += [struct.pack('>I',i)]

        self.seeds_16 = self.seed_int16()
        for i in self.seeds_16:
            self.seeds += [struct.pack('<H',i)]
            self.seeds += [struct.pack('>H',i)]

        self.seeds_8 = self.seed_int8()
        for i in self.seeds_8:
            self.seeds += [struct.pack('B',i)]

    def seed_int32(self):
        ret = []
        def add(ret, i):
            i = i & 0xffffffff
            if i not in ret: ret += [i]

        add(ret, 0)
        for i in xrange(40):
            add(ret, i-(2*i*(i%2)))

        for i in xrange(32):
            add(ret, 2**i)

        for i in xrange(1,5):
            add(ret, 0xffffffff/i) #uint max
            add(ret, 0xffffffff/i-32) #uint max-32
            add(ret, 0xffffffff/i+32) #uint max+32
            add(ret, 0x7fffffff/i) #signed int max
            add(ret, 0x7fffffff/i-32) #signed int max-32
            add(ret, 0x7fffffff/i+32) #signed int max+32

        return ret

    def seed_int16(self):
        ret = []
        def add(ret, i):
            i = i & 0xffff
            if i not in ret: ret += [i]

        add(ret, 0)
        for i in xrange(40):
            add(ret, i-(2*i*(i%2)))

        for i in xrange(16):
            add(ret, 2**i)

        for i in xrange(1,5):
            add(ret, 0xffff/i) #uint max
            add(ret, 0xffff/i-32) #uint max-32
            add(ret, 0xffff/i+32) #uint max+32
            add(ret, 0x7fff/i) #signed int max
            add(ret, 0x7fff/i-32) #signed int max-32
            add(ret, 0x7fff/i+32) #signed int max+32

        return ret

    def seed_int8(self):
        ret = []
        def add(ret, i):
            i = i & 0xff
            if i not in ret: ret += [i]

        add(ret, 0)
        for i in xrange(40):
            add(ret, i-(2*i*(i%2)))

        for i in xrange(8):
            add(ret, 2**i)

        for i in xrange(1,5):
            add(ret, 0xff/i) #uint max
            add(ret, 0xff/i-16) #uint max-32
            add(ret, 0xff/i+16) #uint max+32
            add(ret, 0x7f/i) #signed int max
            add(ret, 0x7f/i-16) #signed int max-32
            add(ret, 0x7f/i+16) #signed int max+32

        return ret

    def seeds_string(self):
        def string(s):
            return self.pascal_string(s) + self.c_string(s)
        ret = []
        ret += string("%n"*16)
        ret += string("B"*0x7f)
        ret += string("B"*0xff)
        #ret += string("%n"*1024)
        #ret += string("%n"*4095)

        for c in "\x00 !\"$%&/()=?,;.:-_#'+*<>|":
            ret += [c*16]
        #ret += self.pascal_string("%n"*0x7fff)
        #ret += self.c_string("%n"*0x7fff)
        return ret

    def pascal_string(self, s):
        ret = []
        l = len(s)
        ret += [struct.pack('<I',(l+16)&0xffffffff)+s]
        ret += [struct.pack('<I',(l)&0xffffffff)+s]
        ret += [struct.pack('<I',(l-16)&0xffffffff)+s]
        ret += [struct.pack('>I',(l+16)&0xffffffff)+s]
        ret += [struct.pack('>I',(l)&0xffffffff)+s]
        ret += [struct.pack('>I',(l-16)&0xffffffff)+s]
        ret += [struct.pack('<H',(l+16)&0xffff)+s]
        ret += [struct.pack('<H',(l)&0xffff)+s]
        ret += [struct.pack('<H',(l-16)&0xffff)+s]
        ret += [struct.pack('>H',(l+16)&0xffff)+s]
        ret += [struct.pack('>H',(l)&0xffff)+s]
        ret += [struct.pack('>H',(l-16)&0xffff)+s]
        ret += [struct.pack('B',(l+16)&0xff)+s]
        ret += [struct.pack('B',(l)&0xff)+s]
        ret += [struct.pack('B',(l-16)&0xff)+s]
        return ret

    def c_string(self, s):
        return [s, s+"\x00"]
