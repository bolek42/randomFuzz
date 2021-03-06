import socket
import json
import struct
import os
import time
from threading import Thread
from multiprocessing import Process,Queue,Value
from base64 import b64encode, b64decode

class api:
    def __init__(self):
        pass

    def recv(self, s):
        while True:
            try: #error: [Errno 4] Interrupted system call
                n = struct.unpack('<I',s.recv(4))[0]
                break
            except:
                pass
        d = ""
        while len(d) < n:
            try:
                d += s.recv(n-len(d))
            except:
                pass
        return json.loads(d)

    def send(self, s, data):
        j = json.dumps(data)
        s.sendall(struct.pack('<I',len(j)))
        s.sendall(j)

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
            try:
                conn, addr = s.accept()
                self.connections += [conn]
                Thread(target=self.client_handler, args=(conn,)).start()
            except:
                pass

    def client_handler(self, conn):
        print "worker connected"
        self.connected_worker.value += 1
        provision = {}
        provision["cmd"] = self.cmd
        provision["env"] = self.env
        provision["seed"] = os.path.basename(self.seed)
        provision["ext"] = self.ext
        provision["coverage"] = self.cast_coverage_to_json(self.coverage)
        provision["crash"] = self.crash

        with open("seeds/" + self.seed, "r") as f:
            provision["seed_data"] = b64encode(f.read())

        #add known testcases
        testcases = []
        last_tid = 0
        while True:
            if not os.path.exists("%s/testcase-%d.json" % (self.seed, last_tid)):
                break
            with open("%s/testcase-%d.json" % (self.seed, last_tid), "r") as f:
                testcases += [b64encode(f.read())]
            last_tid += 1
        provision["testcases"] = b64encode(json.dumps(testcases))

        #add files
        provision["files"] = {}
        print self.files
        for fname in self.files:
            print fname
            f = open("files/"+fname, "rb")
            provision["files"][fname] = b64encode(f.read())
            f.close()

        #provision
        try:
            self.send(conn, provision)
        except:
            return
        
        del provision
        print "worker provisioned"

        #main loop
        while True:
            #send update
            update = {}
            update["testcase_update"] = self.testcases[last_tid:]
            last_tid += len(update["testcase_update"])

            if len(update["testcase_update"]) > 0:
                update["coverage_update"] = self.cast_coverage_to_json(self.coverage)

            update["crash"] = self.crash
            try:
                self.send(conn, update)
            except:
                break

            #process updates
            try:
                report = self.recv(conn)
            except:
                break
            self.total_testcases += report["executed_testcases"]

            self.report_queue.put({"total_testcases":self.total_testcases})
            for testcase in report["testcase_report"]:
                self.report_queue.put(testcase)

            time.sleep(1)

        conn.close()
        self.connected_worker.value -= 1

    def api_stop(self):
        self.sock.close()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", self.port))
            s.close()
        except:
            pass
        for c in self.connections:
            try:
                c.close()
            except:
                pass

    #client
    def connect(self, ip, port):
        #set up socket
        print "connecting %s:%d" % (ip, port)
        self.ip = ip
        self.port = port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(100)
        s.connect((self.ip, self.port))
        self.sock = s
        provision = self.recv(s)

        #generic
        self.cmd = provision["cmd"]
        self.coverage = self.cast_coverage_from_json(provision["coverage"])
        self.crash = provision["crash"]
        self.ext = provision["ext"]
        self.seed = provision["seed"]
        self.seed_data = b64decode(provision["seed_data"])
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

    def client(self, n_testcases):
        executed_testcases_old = 0
        while self.executed_testcases.value < n_testcases or n_testcases == 0:
            #wait for updates
            update = self.recv(self.sock)
            self.apply_update(update)
            for queue in self.update_queues:
                queue.put(update)

            if len(update["testcase_update"]) > 0:
                cov = ""
                for x in self.coverage.keys():
                    cov = "%s: %d  " % (x, len(self.coverage[x]))
                print "Got %d new Testcases %d Total; Coverage: %s" % (len(update["testcase_update"]), len(self.testcases), cov)

            #report
            report = {}
            report["testcase_report"] = []
            i = 0
            #get report with most new_blocks from queue
            while self.testcase_report.qsize() > 0 and i < 10:
                t = t0 = t_max = self.testcase_report.get()
                self.testcase_report.put(t0)
                while t != t0:
                    t = self.testcase_report.get()
                    self.testcase_report.put(t)
                    if t["new_blocks"] > t_max["new_blocks"]:
                        t_max = t
 
                t = self.testcase_report.get()
                while t != t_max:
                    t = self.testcase_report.get()
                    self.testcase_report.put(t)

                t["coverage"] = self.cast_coverage_to_json(t["coverage"])
                report["testcase_report"].append(t)
                i += 1

            report["executed_testcases"] = self.executed_testcases.value - executed_testcases_old
            executed_testcases_old =  self.executed_testcases.value
                
            self.send(self.sock, report)

    def cast_coverage_from_json(self, coverage):
        new_blocks = 0
        ret = {}
        for k in coverage:
            ret[k] = set(coverage[k])
        return ret

    def cast_coverage_to_json(self, coverage):
        new_blocks = 0
        ret = {}
        for k in coverage:
            ret[k] = list(coverage[k])
        return ret

    def compute_new_blocks(self, coverage, ref=None):
        if ref is None:
            ref = self.coverage
        new_blocks = 0
        for k in coverage:
            if k in ref:
                new_blocks += len(coverage[k].difference(ref[k]))
            else:
                new_blocks += len(coverage[k])
        return new_blocks

    def coverage_update(self, ref, coverage):
        for k in coverage:
            if k in ref:
                ref[k].update(coverage[k])
            else:
                ref[k] = coverage[k]
