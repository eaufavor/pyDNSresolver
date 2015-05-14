#!/usr/bin/env python

# credit https://gist.github.com/andreif/6069838
import sys
sys.path.append("./dnspython/")
sys.path.append("./dnslib/")
from dns import resolver, message, query, exception, rdatatype
import time
import multiprocessing.pool
import multiprocessing
import datetime
import threading
import traceback
import SocketServer
import random
import dnslib
from dnslib import *

#http://pcsupport.about.com/od/tipstricks/a/free-public-dns-servers.htm
#http://www.tech-faq.com/public-dns-servers.html
#'223.5.5.5'
cache = {}
#DNSlist = ['128.2.184.224', '8.8.8.8', '208.67.222.222', '209.244.0.3', '8.26.56.26',\
# '74.82.42.42', '151.197.0.38']
DNSlist = ['8.8.8.8']
PORT = 53
TTL = 20

UCLADNS = '204.194.237.21'
OKSUDNS = '139.78.100.1'
NYITDNS = '167.206.4.141'

CASERVICE = '52.8.69.95'
VASERVICE = '52.5.82.56'

smartList = {'lb2.sid.eaufavor.info.': \
                {
                    'NYITDNS':[CASERVICE, VASERVICE, VASERVICE, VASERVICE],
                    'default':['8.9.10.13', '8.9.10.14'],
                }
            }

def smartLookup(domain, client):
    if client in smartList[domain]:
        return random.choice(smartList[domain][client])
    else:
        print 'new cient', client
        return random.choice(smartList[domain]['default'])


def fetch(dns_index_req):
    dns_index = dns_index_req[0]
    domain = dns_index_req[1].lower()
    query_type = dns_index_req[2]
    client = dns_index_req[3]
    if domain in smartList:
        ip = smartLookup(domain, client)
        return ([ip], 0)
    q = message.make_query(domain, query_type)
    rcode = q.rcode()
    count = 0
    while True and count < 3:
        try:
            msg = query.udp(q, DNSlist[dns_index], timeout=1)
        except exception.Timeout:
            count += 1
            continue
        break
    if count >= 3:
        return ([], rcode)
    ips = []
    #print msg.answer
    answer = None
    for anss in msg.answer:
        #print "Type", rdatatype.to_text(anss.to_rdataset().rdtype)
        if anss.to_rdataset().rdtype == query_type: #match record type
            answer = anss
    if answer is None:
        return (ips, rcode)
    for ans in answer:
        ips.append(ans.to_text())
    return (ips, rcode)

def dns_response(data, client):
    request = DNSRecord.parse(data)
    print request
    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
 
    qname = request.q.qname
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]

    rcode = 0

    dns_index_req = []
    for i in range(len(DNSlist)):
        dns_index_req.append((i, qn, qtype, client))

    if qn not in smartList and (qn, qtype) in cache:
        answers = cache[(qn, qtype)]
    else:
        answers = p.map_async(fetch, dns_index_req).get(9999)
        cache[(qn, qtype)] = answers

    ans_pool = {}
    record_class = getattr(dnslib, str(qt))
    empty_ans = True
    if qtype == QTYPE.A:
        for ans in answers:
            if rcode == 0:
                rcode = ans[1]
            for a in ans[0]:
                if '.'.join(a.split(".")[:3]) not in ans_pool: #ignore the IP from same subnet 
                    empty_ans = False
                    reply.add_answer(RR(rname=qname, rtype=qtype,\
                                 rclass=1, ttl=TTL, rdata=record_class(a)))
                    ans_pool['.'.join(a.split(".")[:3])] = 1
                else:
                    pass
    else:
        for ans in answers:
            if rcode == 0:
                rcode = ans[1]
            for a in ans[0]:
                if a not in ans_pool: # reduce redundancy
                    empty_ans = False
                    reply.add_answer(RR(rname=qname, rtype=qtype, rclass=1,\
                                 ttl=TTL, rdata=record_class(a)))
                    ans_pool[a] = 1

    #print "---- Reply:\n", reply
    if empty_ans and rcode > 0:
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1,\
                 rcode=rcode), q=request.q)
    return reply.pack()


class BaseRequestHandler(SocketServer.BaseRequestHandler):
 
    def get_data(self):
        raise NotImplementedError
 
    def send_data(self, data):
        raise NotImplementedError
 
    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        print "\n\n%s request %s (%s %s):" % (self.__class__.__name__[:3],\
                     now, self.client_address[0], self.client_address[1])
        try:
            data = self.get_data()
            print len(data), data.encode('hex')  # repr(data).replace('\\x', '')[1:-1]
            self.send_data(dns_response(data, self.client_address[0]))
        except Exception:
            traceback.print_exc(file=sys.stderr)
 
 
class TCPRequestHandler(BaseRequestHandler):
 
    def get_data(self):
        data = self.request.recv(8192)
        sz = int(data[:2].encode('hex'), 16)
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]
 
    def send_data(self, data):
        sz = hex(len(data))[2:].zfill(4).decode('hex')
        return self.request.sendall(sz + data)
 
 
class UDPRequestHandler(BaseRequestHandler):
 
    def get_data(self):
        return self.request[0]
 
    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)





if __name__ == '__main__':
    print "Starting nameserver..."
 
    servers = [
        SocketServer.ThreadingUDPServer(('', PORT), UDPRequestHandler),
        SocketServer.ThreadingTCPServer(('', PORT), TCPRequestHandler),
    ]
    for s in servers:
        thread = threading.Thread(target=s.serve_forever)
          # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        print "%s server loop running in thread: %s" %\
                    (s.RequestHandlerClass.__name__[:3], thread.name)
    p = multiprocessing.Pool(30)
    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()
 
    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()


