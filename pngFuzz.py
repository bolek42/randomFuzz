from mutationFuzz import *
from randomFuzz import *
import os
from binascii import crc32, unhexlify, hexlify

chunk_types = ["IHDR","JHDR","MHDR","PLTE","IDAT","IEND","bKGD","cHRM","fRAc","gAMA","gIFg","gIFt","gIFx","hIST","iCCP","iTXt","oFFs","pCAL","pHYs","sBIT","sCAL","sPLT","sRGB","sTER","tEXt","zTXt","tEXt","tIME","tRNS","cmOD","cmPP","cpIp","mkBF","mkBS","mkBT","mkTS","pcLb","prVW","spAL","JDAT","JSEP","DHDR","FRAM","SAVE","SEEK","nEED","DEFI","BACK","MOVE","CLON","SHOW","CLIP","LOOP","ENDL","PROM","fPRI","eXPI","BASI","IPNG","PPLT","PAST","TERM","DISC","pHYg","DROP","DBYK","ORDR","MAGN","MEND","Disc"]

def fix_png(d):
    global chunk_types
    i = 8
    while i < len(d):
        #determine l
        l = 2**31
        for T in chunk_types:
            try:
                l = min(d[i+8:].lower().index(T.lower())-8,l)
            except:
                pass
        d = d[:i] + struct.pack('>I',max(0,l)) + d[i+4:]
        t = d[i+4:i+8] #type
        data = d[i+8:i+8+l] #data

        #attempt to fix crc
        try:
            crc = struct.unpack('>i',d[i+8+l:i+8+l+4])[0] #crc
            d = d[:i+8+l] + struct.pack('>i',crc32(t+data)) + d[i+8+l+4:]
        except:
            pass

        i += l + 12
    return d

def read_png(d):
    global chunk_types
    i = 8
    while i < len(d):
        #determine l
        l = 2**31
        for T in chunk_types:
            try:
                l = min(d[i+8:].lower().index(T.lower())-8,l)
            except:
                pass
        d = d[:i] + struct.pack('>I',max(0,l)) + d[i+4:]
        t = d[i+4:i+8] #type
        data = d[i+8:i+8+l] #data

        #attempt to fix crc
        try:
            crc = struct.unpack('>i',d[i+8+l:i+8+l+4])[0] #crc
            d = d[:i+8+l] + struct.pack('>i',crc32(t+data)) + d[i+8+l+4:]
        except:
            pass
	print t, hexlify(struct.pack('>I',max(0,l))+t+data+struct.pack('>i',crc32(t+data)))

        i += l + 12
    return d
for fname in sys.argv[1:]:
	with open(fname, "r") as f:
		d= f.read()
		read_png(d)
#sys.exit(1)
#img = unhexlify("89504e470d0a1a0a")
#img += unhexlify("0000000d4948445200000001000000010802000000907753de")
#img += unhexlify("0000000467414d4100010175b393be88")#gamma
#img += unhexlify("0000002c74455874436f7079726967687400a920323031332c32303135204a6f686e2043756e6e696e6768616d20426f776c65727d7473fe")#text
#img += unhexlify("00000074695458744c6963656e73696e67000100656e000008d72d8c4d0e83201085aff2e2011cbb6d97781184974a220c81b10b4faf095d7f3f2b630ade18610adb897a6e470a889a7d2aa86c708dded28f709ab3968e87b37462726ec16b5ea60f76b3dadf22e1ef86a1cedabe328e6328179bcad3c80d33322a82d898ad26")#itxt
#img += unhexlify("00000001735247420337c74d53")#srgb
#img += unhexlify("0000000674524e5300010001000125037480")#trns
#img += unhexlify("000000007a5458746b797bf1")#ztxt
#img += unhexlify("00000019446973636c61696d65720000789c732b4a4d2d4f2c4ad503001155036033fde8f4")#Disc
#img += unhexlify("0000000774494d4507b201010000001e0a560b")#time
#img += unhexlify("0000087a73504c547369782d63756265001000000000000000ff000000000000003300ff000000000000006600ff000000000000009900ff00000000000000cc00ff00000000000000ff00ff000000000033000000ff000000000033003300ff000000000033006600ff000000000033009900ff00000000003300cc00ff00000000003300ff00ff000000000066000000ff000000000066003300ff000000000066006600ff000000000066009900ff00000000006600cc00ff00000000006600ff00ff000000000099000000ff000000000099003300ff000000000099006600ff000000000099009900ff00000000009900cc00ff00000000009900ff00ff0000000000cc000000ff0000000000cc003300ff0000000000cc006600ff0000000000cc009900ff0000000000cc00cc00ff0000000000cc00ff00ff0000000000ff000000ff0000000000ff003300ff0000000000ff006600ff0000000000ff009900ff0000000000ff00cc00ff0000000000ff00ff00ff000000330000000000ff000000330000003300ff000000330000006600ff000000330000009900ff00000033000000cc00ff00000033000000ff00ff000000330033000000ff000000330033003300ff000000330033006600ff000000330033009900ff00000033003300cc00ff00000033003300ff00ff000000330066000000ff000000330066003300ff000000330066006600ff000000330066009900ff00000033006600cc00ff00000033006600ff00ff000000330099000000ff000000330099003300ff000000330099006600ff000000330099009900ff00000033009900cc00ff00000033009900ff00ff0000003300cc000000ff0000003300cc003300ff0000003300cc006600ff0000003300cc009900ff0000003300cc00cc00ff0000003300cc00ff00ff0000003300ff000000ff0000003300ff003300ff0000003300ff006600ff0000003300ff009900ff0000003300ff00cc00ff0000003300ff00ff00ff000000660000000000ff000000660000003300ff000000660000006600ff000000660000009900ff00000066000000cc00ff00000066000000ff00ff000000660033000000ff000000660033003300ff000000660033006600ff000000660033009900ff00000066003300cc00ff00000066003300ff00ff000000660066000000ff000000660066003300ff000000660066006600ff000000660066009900ff00000066006600cc00ff00000066006600ff00ff000000660099000000ff000000660099003300ff000000660099006600ff000000660099009900ff00000066009900cc00ff00000066009900ff00ff0000006600cc000000ff0000006600cc003300ff0000006600cc006600ff0000006600cc009900ff0000006600cc00cc00ff0000006600cc00ff00ff0000006600ff000000ff0000006600ff003300ff0000006600ff006600ff0000006600ff009900ff0000006600ff00cc00ff0000006600ff00ff00ff000000990000000000ff000000990000003300ff000000990000006600ff000000990000009900ff00000099000000cc00ff00000099000000ff00ff000000990033000000ff000000990033003300ff000000990033006600ff000000990033009900ff00000099003300cc00ff00000099003300ff00ff000000990066000000ff000000990066003300ff000000990066006600ff000000990066009900ff00000099006600cc00ff00000099006600ff00ff000000990099000000ff000000990099003300ff000000990099006600ff000000990099009900ff00000099009900cc00ff00000099009900ff00ff0000009900cc000000ff0000009900cc003300ff0000009900cc006600ff0000009900cc009900ff0000009900cc00cc00ff0000009900cc00ff00ff0000009900ff000000ff0000009900ff003300ff0000009900ff006600ff0000009900ff009900ff0000009900ff00cc00ff0000009900ff00ff00ff000000cc0000000000ff000000cc0000003300ff000000cc0000006600ff000000cc0000009900ff000000cc000000cc00ff000000cc000000ff00ff000000cc0033000000ff000000cc0033003300ff000000cc0033006600ff000000cc0033009900ff000000cc003300cc00ff000000cc003300ff00ff000000cc0066000000ff000000cc0066003300ff000000cc0066006600ff000000cc0066009900ff000000cc006600cc00ff000000cc006600ff00ff000000cc0099000000ff000000cc0099003300ff000000cc0099006600ff000000cc0099009900ff000000cc009900cc00ff000000cc009900ff00ff000000cc00cc000000ff000000cc00cc003300ff000000cc00cc006600ff000000cc00cc009900ff000000cc00cc00cc00ff000000cc00cc00ff00ff000000cc00ff000000ff000000cc00ff003300ff000000cc00ff006600ff000000cc00ff009900ff000000cc00ff00cc00ff000000cc00ff00ff00ff000000ff0000000000ff000000ff0000003300ff000000ff0000006600ff000000ff0000009900ff000000ff000000cc00ff000000ff000000ff00ff000000ff0033000000ff000000ff0033003300ff000000ff0033006600ff000000ff0033009900ff000000ff003300cc00ff000000ff003300ff00ff000000ff0066000000ff000000ff0066003300ff000000ff0066006600ff000000ff0066009900ff000000ff006600cc00ff000000ff006600ff00ff000000ff0099000000ff000000ff0099003300ff000000ff0099006600ff000000ff0099009900ff000000ff009900cc00ff000000ff009900ff00ff000000ff00cc000000ff000000ff00cc003300ff000000ff00cc006600ff000000ff00cc009900ff000000ff00cc00cc00ff000000ff00cc00ff00ff000000ff00ff000000ff000000ff00ff003300ff000000ff00ff006600ff000000ff00ff009900ff000000ff00ff00cc00ff000000ff00ff00ff00ff000096d08b86")
#img += unhexlify("000000206348524d00007a26000080840000fa00000080e8000075300000ea6000003a98000017709cba513c") #chrm
#img += unhexlify("000000037342495404040477f8b5a3")#sbit
#img += unhexlify("000000097048597300000001000000040032523093")#phys
#img += unhexlify("00000300504c5445ffffffefefffdfdfffcfcfffbfbfffafafff9f9fff8f8fff8080ff7070ff6060ff5050ff4040ff3030ff2020ff1010ffffefefefe1efdfd3efcfc5efbfb7efafa9ef9f9bef8f8def8080ef7072ef6064ef5056ef4048ef303aef202cef101eefffdfdfefd3dfdfc7dfcfbbdfbfafdfafa3df9f97df8f8bdf8080df7074df6068df505cdf4050df3044df2038df102cdfffcfcfefc5cfdfbbcfcfb1cfbfa7cfaf9dcf9f93cf8f89cf8080cf7076cf606ccf5062cf4058cf304ecf2044cf103acfffbfbfefb7bfdfafbfcfa7bfbf9fbfaf97bf9f8fbf8f87bf8080bf7078bf6070bf5068bf4060bf3058bf2050bf1048bfffafafefa9afdfa3afcf9dafbf97afaf91af9f8baf8f85af8080af707aaf6074af506eaf4068af3062af205caf1056afff9f9fef9b9fdf979fcf939fbf8f9faf8b9f9f879f8f839f80809f707c9f60789f50749f40709f306c9f20689f10649fff8f8fef8d8fdf8b8fcf898fbf878faf858f9f838f8f818f80808f707e8f607c8f507a8f40788f30768f20748f10728fff8080ef8080df8080cf8080bf8080af80809f80808f8080808080708080608080508080408080308080208080108080ff7070ef7270df7470cf7670bf7870af7a709f7c708f7e70808070708170608370508570408770308970208b70108d70ff6060ef6460df6860cf6c60bf7060af74609f78608f7c60808060708360608760508b60408f60309360209760109b60ff5050ef5650df5c50cf6250bf6850af6e509f74508f7a50808050708550608b50509150409750309d5020a35010a950ff4040ef4840df5040cf5840bf6040af68409f70408f7840808040708740608f40509740409f4030a74020af4010b740ff3030ef3a30df4430cf4e30bf5830af62309f6c308f7630808030708930609330509d3040a73030b13020bb3010c530ff2020ef2c20df3820cf4420bf5020af5c209f68208f7420808020708b2060972050a32040af2030bb2020c72010d320ff1010ef1e10df2c10cf3a10bf4810af56109f64108f7210808010708d10609b1050a91040b71030c51020d31010e110940a6e1c")#plte
#img += unhexlify("0000001e6849535400400070003000600060002000200050001000800040001000300050007048995941")#hist
#
#img += unhexlify("00000006624b474400000000ffff4765a980")#bkgd
#img += unhexlify("0000000c4944415418d363641ce1000082820102317df498")#IDAT
#img += unhexlify("8000000049454e44ae426082650377d7")#iend
#
#
#with open("seed-2.png", "w") as f:
#    f.write(fix_png(img))

#with open(sys.argv[1], "r") as f:
#d= f.read()
#d = fix_png(d)
#with open(sys.argv[2], "w") as f:
#    f.write(img)
#sys.exit(1)

def seeds():
	seeds = chunk_types[:]
	return map(lambda x: "AAAA" + x + "BBBB", seeds)

    
def mutate_callback(self, testcase):
    try:
        seed = self.seed
    except:
        with open("../seed-1.png", "r") as f:
            seed = f.read()
            self.seed = seed

    try:
        m = self.mutator
    except:
        m = mutator(seeds())
        self.mutator = m

    data = m.mutate_seed(testcase, seed)
    data = fix_png(data)
    testcase["len"] = len(data)
    return data

os.chdir("teststuff")

#f = randomFuzz(   "./pngimage --test-all %s",
#                    ["../pngimage","../libpng16.so.16", "../seed-1.png"],
#                    seeds,
#                    "pngimage-work", 
#                    mutate_callback)

f = randomFuzz(     ["./pngimage --test-all %s"],#, "pngcheck %s", "convert %s -thumbnail 10x10 ./null.jpg"],
                    ["../pngimage"],
                    seeds(),
                    "pngimage-work", 
                    mutate_callback)
f.launch()


from generator import *
from genoFuzz import *
class png_generator(generator):
    png_magic = unhexlify("89504e470d0a1a0a")

    def create_chunk(self, t, data):
        chunk = struct.pack('>I',len(data))
        chunk += self.value("blob", "name-"+t, t)
        chunk += data
        chunk += struct.pack('>i',crc32(t+data))
        return chunk

    def ihdr(self):
        ret = ""
        ret += self.value("uint32", "ihdr-width", 1)
        ret += self.value("uint32", "ihdr-heigth", 1)
        ret += self.value("uint8", "ihdr-bitdepth", 8)
        ret += self.value("uint8", "ihdr-colortype", 2)
        ret += self.value("uint8", "ihdr-compression", 0)
        ret += self.value("uint8", "ihdr-filter", 0)
        ret += self.value("uint8", "ihdr-interlace", 0)
        return ret

    def phys(self):
        return self.value("blob", "phys", unhexlify("00000b1300000b1301"))

    def time(self):
        return self.value("blob", "time", unhexlify("07e005070d2a1b"))

    def text(self):
        ret = self.value("string", "text-key", "Comment\x00")
        ret += self.value("string", "text-value", "Created with GIMP")
        return ret

    def itxt(self):
        ret = self.value("string", "itxt-key", "Comment\x00")
        ret = self.value("uint8", "itxt-compr", 0)
        ret = self.value("uint8", "itxt-compr-method", 0)
        ret += self.value("string", "itxt-lang", "AAAAAAAAAAAAAA\x00")
        ret += self.value("string", "itxt-transkey", "BBBBBBBBBBBBBB\x00")
        ret += self.value("string", "itxt-text", "CCCCCCCCCCCCCC")
        return ret

    def idat(self):
        return self.value("blob", "idat", unhexlify("08d763f8ffff3f0005fe02fe"))

    def bkgd(self):
        return self.value("blob", "bkgd", unhexlify("00ff00ff00ff"))

    def chrm(self):
        return self.value("blob", "chrm", unhexlify("00007a26000080840000fa00000080e8000075300000ea6000003a9800001770"))

    def chrm(self):
        return self.value("blob", "hIST", unhexlify("4142434445464748"))
            

    def get_data(self, gene):
        self.gene = gene
        ret = self.png_magic
        ret += self.create_chunk("IHDR", self.ihdr())
        ret += self.create_chunk("bKGD", self.bkgd())
        ret += self.create_chunk("pHYs", self.phys())
        ret += self.create_chunk("tIME", self.time())
        ret += self.create_chunk("tEXt", self.text())
        ret += self.create_chunk("iTXt", self.itxt())
        ret += self.create_chunk("cHRM", self.chrm())
        #ret += self.create_chunk("hIST", self.text())
        ret += self.create_chunk("IDAT", self.idat())
        ret += self.create_chunk("IEND", "")
        return ret

def generate_callback(self, gene):
    try:
        seed = self.seed
    except:
        with open("../seed-1.png", "r") as f:
            seed = f.read()
            self.seed = seed

    try:
        generator = self.generator
    except:
        generator = png_generator()
        self.generator = generator

    return generator.get_data(gene)
def call_png(self, testcase):
    #file based
    data = self.callback(self,testcase)

    fname = hex(getrandbits(128))
    with open(fname, "wb") as f:
        f.write(data)

    stderr = ""
    bitsets = {}
    for cmd in self.cmd:
        #call program
        stdin = ""
        cmd = (cmd % fname).split(" ")
        p = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE)
        stdout, err = p.communicate(input=stdin)
        stderr += err

        crash,bitsets = parse_asan(p.pid, stderr)
    os.remove(fname)
    return stderr, crash, bitsets


f = genoFuzz(   "./pngfix %s",
                ["pngfix","libpng16.so.16"],
                ["../pngfix","../libpng16.so.16"],
                "pngfix-geno", 
                generate_callback,
                png_generator)
f.launch()

