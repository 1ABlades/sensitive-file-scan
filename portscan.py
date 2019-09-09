import re
import threading
import queue
import os, sys
import socket

class portscan():
    
    def __init__(self, scanports):
        self.q = queue.Queue()
        self.sp = queue.Queue()
        self.ports = []
        self.pinglist = []
        self.lock = threading.Lock()
        self.signs = self.getsigns('conf/signs.conf')
        self.getports(scanports)
        self.ipdict = {
            "ftp": [],
            "ldap": [],
            "memcache": [],
            "mongodb": [],
            "mysql": [],
            "mssql": [],
            "postgres": [],
            "redis": [],
            "rsync": [],
            "smb": [],
            "ssh": [],
            "ssl": [],
            "web": [],
            "http": [],
            "telnet": [],
            "Unknown": []
        }
        self.PROBES = [
            '\r\n\r\n',
            'GET / HTTP/1.0\r\n\r\n',
            'stats\r\n',            
            'GET / \r\n\r\n',
            '\x01\x00\x00\x00\x01\x00\x00\x00\x08\x08',
            '\x80\0\0\x28\x72\xFE\x1D\x13\0\0\0\0\0\0\0\x02\0\x01\x86\xA0\0\x01\x97\x7C\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0',
            '\x03\0\0\x0b\x06\xe0\0\0\0\0\0',
            '\0\0\0\xa4\xff\x53\x4d\x42\x72\0\0\0\0\x08\x01\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\x06\0\0\x01\0\0\x81\0\x02PC NETWORK PROGRAM 1.0\0\x02MICROSOFT NETWORKS 1.03\0\x02MICROSOFT NETWORKS 3.0\0\x02LANMAN1.0\0\x02LM1.2X002\0\x02Samba\0\x02NT LANMAN 1.0\0\x02NT LM 0.12\0',
            '\x80\x9e\x01\x03\x01\x00u\x00\x00\x00 \x00\x00f\x00\x00e\x00\x00d\x00\x00c\x00\x00b\x00\x00:\x00\x009\x00\x008\x00\x005\x00\x004\x00\x003\x00\x002\x00\x00/\x00\x00\x1b\x00\x00\x1a\x00\x00\x19\x00\x00\x18\x00\x00\x17\x00\x00\x16\x00\x00\x15\x00\x00\x14\x00\x00\x13\x00\x00\x12\x00\x00\x11\x00\x00\n\x00\x00\t\x00\x00\x08\x00\x00\x06\x00\x00\x05\x00\x00\x04\x00\x00\x03\x07\x00\xc0\x06\x00@\x04\x00\x80\x03\x00\x80\x02\x00\x80\x01\x00\x80\x00\x00\x02\x00\x00\x01\xe4i<+\xf6\xd6\x9b\xbb\xd3\x81\x9f\xbf\x15\xc1@\xa5o\x14,M \xc4\xc7\xe0\xb6\xb0\xb2\x1f\xf9)\xe8\x98',
            '\x16\x03\0\0S\x01\0\0O\x03\0?G\xd7\xf7\xba,\xee\xea\xb2`~\xf3\0\xfd\x82{\xb9\xd5\x96\xc8w\x9b\xe6\xc4\xdb<=\xdbo\xef\x10n\0\0(\0\x16\0\x13\0\x0a\0f\0\x05\0\x04\0e\0d\0c\0b\0a\0`\0\x15\0\x12\0\x09\0\x14\0\x11\0\x08\0\x06\0\x03\x01\0',
            '< NTP/1.2 >\n',
            '< NTP/1.1 >\n',
            '< NTP/1.0 >\n',
            '\0Z\0\0\x01\0\0\0\x016\x01,\0\0\x08\0\x7F\xFF\x7F\x08\0\0\0\x01\0 \0:\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\04\xE6\0\0\0\x01\0\0\0\0\0\0\0\0(CONNECT_DATA=(COMMAND=version))',
            '\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x48\x0f\x00\x00',
            '\0\0\0\0\x44\x42\x32\x44\x41\x53\x20\x20\x20\x20\x20\x20\x01\x04\0\0\0\x10\x39\x7a\0\x01\0\0\0\0\0\0\0\0\0\0\x01\x0c\0\0\0\0\0\0\x0c\0\0\0\x0c\0\0\0\x04',
            '\x01\xc2\0\0\0\x04\0\0\xb6\x01\0\0\x53\x51\x4c\x44\x42\x32\x52\x41\0\x01\0\0\x04\x01\x01\0\x05\0\x1d\0\x88\0\0\0\x01\0\0\x80\0\0\0\x01\x09\0\0\0\x01\0\0\x40\0\0\0\x01\x09\0\0\0\x01\0\0\x40\0\0\0\x01\x08\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x01\0\0\x40\0\0\0\x40\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x02\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\0\0\0\0\x01\0\0\x40\0\0\0\0\x04\0\0\0\x04\0\0\x80\0\0\0\x01\x04\0\0\0\x04\0\0\x80\0\0\0\x01\x04\0\0\0\x03\0\0\x80\0\0\0\x01\x04\0\0\0\x04\0\0\x80\0\0\0\x01\x08\0\0\0\x01\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x10\0\0\0\x01\0\0\x80\0\0\0\x01\x10\0\0\0\x01\0\0\x80\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x09\0\0\0\x01\0\0\x40\0\0\0\x01\x09\0\0\0\x01\0\0\x80\0\0\0\x01\x04\0\0\0\x03\0\0\x80\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\x01\x04\0\0\x01\0\0\x80\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\x40\0\0\0\x01\0\0\0\0\x01\0\0\x40\0\0\0\0\x20\x20\x20\x20\x20\x20\x20\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe4\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x7f',
            '\x41\0\0\0\x3a\x30\0\0\xff\xff\xff\xff\xd4\x07\0\0\0\0\0\0test.$cmd\0\0\0\0\0\xff\xff\xff\xff\x1b\0\0\0\x01serverStatus\0\0\0\0\0\0\0\xf0\x3f\0'
        ]
    
    def getports(self, scan_ports):
        if scan_ports == '':
            self.ports = [21, 22, 23, 80, 81, 443, 389, 445, 843, 873, 1043, 1099, 1194, 1433, 1434, 1521, 2601, 2604,
                          3306, 3307, 3128, 3389, 3812, 4440, 4848, 5432, 5900, 5901, 5902, 5903, 6082, 6000, 6379,
                          7001, 7002, 8080, 8181, 8888, 8090, 8000, 8008, 8009, 8081, 8088, 8089, 9000, 9080, 9043,
                          9090, 9091, 9200, 9528, 10000, 11211, 10022, 15000, 16000, 22022, 22222, 27017, 28017, 17017,
                          18017, 11321, 50060]
        else:
            try:
                if scan_ports.find(",") > 0:
                    for port in scan_ports.strip().split(','):
                        self.ports.append(int(port))
                elif scan_ports.find("-") > 0: 
                    startport = int(scan_ports.strip().split('-')[0])
                    endport = int(scan_ports.strip().split('-')[1])
                    for i in xrange(startport, endport + 1):
                        self.ports.append(i)
                else:
                    self.ports.append(int(scan_ports))
            except:
                print('[!]not a vaild ports given. you should put ip like 22,80 or 1-65535')
                exit()
    #文件转字典
    def getsigns(self, file):
        iplist = []
        try:
            fh = open(file)
            for ip in fh.readlines():
                ip = ip.strip()
                iplist.append(ip)
            fh.close()
        except Exception as error:
            print(error)
            os._exit(0)

        signlist = []
        for item in iplist:
            (label, pattern) = item.split('|', 2)
            sign = (label, pattern)
            signlist.append(sign)
        return signlist

    def matchbanner(self, banner, slist):
        for item in slist:
            p = re.compile(item[1])
            if p.search(banner) != None:
                return item[0]
        return 'Unknown'


    def getIplist(self, ip):
        iplist = []
        iptonum = lambda x: sum([256 ** j * int(i) for j, i in enumerate(x.split('.')[::-1])])
        numtoip = lambda x: '.'.join([str(x / (256 ** i) % 256) for i in range(3, -1, -1)])
        if '-' in ip:
            iprange = ip.split('-')
            ipstart = int(iptonum(iprange[0]))
            ipend = int(iptonum(iprange[1]))
            ipcount = ipend - ipstart
            if ipcount >= 0 and ipcount <= 65535:
                for ipnum in range(ipstart, ipend + 1):
                    iplist.append(numtoip(ipnum))
            else:
                print('[!]Please input right ip like 192.168.1, 192.168.1.1, 192.168.1.1-192.168.1.255 or put that in ip.ini')
        elif 'ip.ini' in ip:
            ipfile= open(ip, 'r')
            for ip in ipfile:
                iplist.extend(self.getIplist(ip.strip()))
            ipfile.close()
        else:
            ipsplit = ip.strip().split('.')
            net = len(ipsplit)
            if net == 2:
                for b in range(1, 255):
                    for c in range(1, 255):
                        ip = "%s.%s.%d.%d" % (ipsplit[0], ipsplit[1], b, c)
                        iplist.append(ip)
            elif net == 3:
                for c in range(1, 255):
                    ip = "%s.%s.%s.%d" % (ipsplit[0], ipsplit[1], ipsplit[2], c)
                    iplist.append(ip)
            elif net == 4:
                iplist.append(ip)
            else:
                print("[!]Please input right ip like 192.168.1, 192.168.1.1, 192.168.1.1-192.168.1.255 or put that in ip.ini")
        #print(iplist)
        return iplist


    def pinger(self):
        while True:
            ip = self.q.get()
            cmd = 'ping -n 2 ' + ip
            p = os.popen(cmd, 'r')
            #print(p.read())
            m = re.findall('TTL', p.read())
            if m:
                self.pinglist.append(ip)
                self.lock.acquire()
                print("[+]%s is live\r\n" % ip)
                self.lock.release()
            self.q.task_done()

    def pingscan(self, isping, threads, ips):
        print("[-]Scanning for live machines...")
        if isping == 1:
            print("[-]Start scanning...")
            for i in range(threads):
                t = threading.Thread(target=self.pinger)
                t.setDaemon(True)
                t.start()
            for ip in ips:
                self.q.put(ip)
            self.q.join()
        else:
            self.pinglist = ips
        if len(self.pinglist) == 0:
            print("[!]Not find any live machine")
            os._exit(0)
        #print("[-]Scanning for live machines done")

    #扫描端口服务
    def scanserv(self):
        while True:
            ip, port = self.sp.get()
            #print(ip, port)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            service = 'Unknown'
            try:
                s.connect((ip, port))
            except:
                self.sp.task_done()
                continue

            try:
                result = s.recv(256)
                service = self.matchbanner(result, self.signs)
            except:
                for probe in self.PROBES:
                    #print(probe)
                    try:
                        s.close()
                        sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sd.settiomeout(5)
                        sd.connect((ip, port))
                        sd.send(porbe)
                    except: 
                        continue
                    try:
                        result = sd.recv(256)
                        sevice = self.matchbanner(result, self.signs)
                        if sevice != 'Unknown':
                            break
                    except:
                        continue

            if service not in self.ipdict:
                self.ipdict[service] = []
                self.ipdict[service].append(ip + ':' + str(port))
                self.lock.acquire()
                print('[+]%s opening %s' % (ip, port))
                self.lock.release()
            else:
                self.ipdict[service].append(ip + ':' + str(port))
                self.lock.acquire()
                print('[+]%s opening %s' % (ip, port))
                self.lock.release()

            self.sp.task_done()
            
    #扫描端口
    def scanports(self, threads, file):
        print("[-]Start scanning ports...")
        for i in range(threads):
            st = threading.Thread(target=self.scanserv)
            st.setDaemon(True)
            st.start()
        
        for ip in self.pinglist:
            for port in self.ports:
                self.sp.put((ip, port))
        self.sp.join()
        
        #print("[-]Scanning ports done")

        for name in self.ipdict.keys():
            if len(self.ipdict[name]):
                contents = str(name) + 'service has:\n' + '       ' + str(self.ipdict[name]) + '\n'
                f2 = open(file, 'a+')
                f2.write(contents)
                f2.close()    

    def Unknownserv(self):
        for ip in self.ipdict['Unknown']:
            try:
                if str(ip).split(':')[1] == '21':
                    self.ipdict['ftp'].append(ip)
                if str(ip).split(':')[1] == '389':
                    self.ipdict['ldap'].append(ip)
                if str(ip).split(':')[1] == '445':
                    self.ipdict['smb'].append(ip)
                if str(ip).split(':')[1] in ['3306', '3307', '3308', '3309']:
                    self.ipdict['mysql'].append(ip)
                if str(ip).split(':')[1] == '1433':
                    self.ipdict['mssql'].append(ip)
                if str(ip).split(':')[1] in ['10022', '22']:
                    self.ipdict['ssh'].append(ip)
                if str(ip).split(':')[1] == '27017':
                    self.ipdict['mongodb'].append(ip)
                if str(ip).split(':')[1] == '5432':
                    self.ipdict['postgres'].append(ip)
                if str(ip).split(':')[1] == '443':
                    self.ipdict['ssl'].append(ip)
                if str(ip).split(':')[1] == '873':
                    self.ipdict['rsync'].append(ip)
                if str(ip).split(':')[1] == '11211':
                    self.ipdict['memcache'].append(ip)
                if str(ip).split(':')[1] == '6379':
                    self.ipdict['redis'].append(ip)
                if str(ip).split(':')[1] == '23':
                    self.ipdict['telnet'].append(ip)
            except Exception as e:
                print("[!]error: %s" %e)




    def run(self, isping, threads, ips, file):
        ip = self.getIplist(ips)
        self.pingscan(isping, threads, ip)
        self.scanports(threads, file)
        self.Unknownserv()

if __name__ == '__main__':
    ports=''
    portscan = portscan(ports)
    portscan.run(1, 50, 'http://34.203.233.16', 'result/res.txt')


