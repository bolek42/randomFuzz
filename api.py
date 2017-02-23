import socket
import json
import struct
from threading import Thread
from multiprocessing import Process,Queue,Value
from base64 import b64encode, b64decode

class api:
    def __init__(self):
        pass

    def recv(self, conn):
        n = struct.unpack('<I',s.recv(4))[0]
        d = ""
        while len(d) < n:
            d += s.recv(n-len(d))
        return json.loads(d)

    def send(self, conn, data):
        j = json.dumps(data)
        conn.sendall(struct.pack('<I',len(j)))
        conn.sendall(j)

    #server
    def accept(self, port):
        self.connected_worker = Value('i', 0)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(100)
        s.bind(("0.0.0.0", port))
        s.listen(1)
        s.setblocking(1)
        self.sock = s
        while True:
            conn, addr = s.accept()
            self.connections += [conn]
            Thread(target=self.client_handler, args=(conn,)).start()

    def client_handler(self, conn):
        print "worker connected"
        self.connected_worker.value += 1
        provision = {}
        provision["cmd"] = self.cmd
        provision["env"] = self.env
        provision["seed"] = self.seed
        provision["ext"] = self.ext
        provision["coverage"] = self.coverage
        provision["crash"] = self.crash

        #add known testcases
        testcases = []
        last_tid = len(self.testcases)
        for i in xrange(last_tid):
            with open("testcase-%d.json" % i, "r") as f:
                testcases += [b64encode(f.read())]
        provision["testcases"] = b64encode(json.dumps(testcases))

        #add files
        provision["files"] = {}
        for fname in self.files:
            f = open(fname, "rb")
            provision["files"][fname] = b64encode(f.read())
            f.close()

        #provision
        self.send(conn, provision)
        del provision
        print "worker provisioned"

        #main loop
        while True:
            #send update
            update = {}
            update["testcase_update"] = self.testcases[last_tid:]
            last_tid += len(update["testcase_update"])

            update["coverage_update"] = {}
            if len(update["testcase_update"]) > 0:
                update["coverage_update"] = self.coverage

            update["crash"] = self.crash
            try:
                self.send(conn, update)
            except:
                break

            #process updates
            report = self.recv(conn)
            self.total_testcases += report["executed_testcases"]

            for testcase in report["testcase_report"]:
                self.report_queue.put(testcase)

        conn.close()
        self.connected_worker.value -= 1

    def api_stop(self):
        self.sock.close()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", self.port))
        s.close()
        for c in self.connections:
            try:
                c.close()
            except:
                pass

    #client
    def connect(self, ip, port):
        #set up socket
        print "connecting %s:%d" % (self.ip, self.port)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(100000)
        s.connect((self.ip, self.port))
        self.sock = s
        provision = self.recv(s)

        #generic
        self.cmd = provision["cmd"]
        self.coverage = provision["coverage"]
        self.crash = provision["crash"]
        self.ext = provision["ext"]
        for k in provision["env"]:
            os.environ[k] = provision["env"][k]

        #load testcases
        for t in json.loads(b64decode(provision["testcases"])):
            self.testcases += [json.loads(b64decode(t))]

        #write Files to Disk
        os.chdir(self.workdir)
        for fname, data in provision["files"].iteritems():
            try:
                print "received %s %dkB" % (fname, len(data)/1024)
                f = open(fname, "w")
                f.write(b64decode(data))
                f.close()
                os.chmod(fname, 0700)
            except:
                import traceback; traceback.print_exc()

        ##prepare workdir
        #for fname in glob.glob("*sancov") + glob.glob("t-*"):
        #    os.remove(fname)

        #cleanup
        del provision
        print "privision done"
