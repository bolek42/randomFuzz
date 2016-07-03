import glob
from multiprocessing import Process,Queue,cpu_count
import time
import os

#watchdog terminates processes after timeout
#and delete left files
class watchDog:
    def __init__(self):
        self.watchDogQueue = Queue()
        d = Process(target=self.watchdog, args=())
        d.daemon=True
        d.start()

    def start(self, pid, files):
            self.watchDogQueue.put((time.time(), pid, files))

    def watchdog(self):
        print "watchdog started"
        timeout = 1
        while True:
            t,pid,files = self.watchDogQueue.get()
            t2 = time.time()
            time.sleep(max(0,t+timeout-t2))
            try:
                os.kill(pid, 9)
                print "%d Hung" % pid
            except:
                pass
            for fname in files:
                try:
                    os.remove(sname)
                except:
                    pass

#parses asan and bitset files
def parse_asan(pid, stderr):
    bitsets = {}
    for sname in glob.glob("*.%d.bitset-sancov" % (pid)):
        f = open(sname)
        bitsets[".".join(sname.split(".")[:-2])] = int("1"+f.read(),2)
        os.remove(sname)

    for sname in glob.glob("*.%d.sancov" % (pid)):
        os.remove(sname)

    # log crash
    crash = False
    if "ERROR: AddressSanitizer: heap-buffer-overflow" in stderr:
        errorline = re.findall( "ERROR\: AddressSanitizer: .*", stderr)[0]
        crash = re.findall("0x[0-9a-f]*", errorline)[1]
    elif "ERROR: AddressSanitizer: attempting free on address which was not malloc()-ed:" in stderr:
        errorline = re.findall( "ERROR\: AddressSanitizer: .*", stderr)[0]
        crash = re.findall("0x[0-9a-f]*", errorline)[0]
    elif "ERROR: AddressSanitizer:" in stderr:
        crash = "0x424242"

    if crash:
        print "Crash: " + crash
    return crash, bitsets
