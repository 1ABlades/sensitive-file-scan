import re
import requests
import threading
import queue
import os
import hashlib

class cmsscan(object):
    def __init__(self, url, threads=50):
        self.url = url
        self.filepath = 'data/'
        self.q = queue.Queue()
        self.threads = threads
        self.isknow = False
        self.knew = 0

    #处理request异常
    def requests(self, url):    
        try:
            r = requests.get(url, timeout=10)
        except requests.exceptions.Timeout as e:
            print(e)
            return False
        except requests.exceptions.MissingSchema as e:
            print(e)
            return False
        except requests.exceptions.RequestException as e:
            print(e)
            return False
        return r.text if r.status_code == 200 else False

    #获取ico的MD5
    def getmd5info(self, path='/favicon.ico'):
        url = self.url + path
        response = self.requests(url)
        if response:
            md5 = hashlib.md5()
            md5.update(response.encode('utf-8'))
            return md5.hexdigest()
        return False

    #获取文件内容
    def readfile(self, filename):
        filename = self.filepath + filename
        with open(filename, 'r') as f:
            return f.readlines()

    def compareico(self):
        res = self.getmd5info()
        if res != False:
            for line in self.readfile('ico.txt'):
                if res == line.strip().split('#')[1]:
                    print('[*]Based on favicon.ico: ', line.strip().split('#')[0])
                    return True
            print('[-]Based on favicon.ico: Unknown')
        
    def getfeature(self):
        files = os.listdir(self.filepath)
        files.remove('ico.txt')
        for f in files:
            i = 0
            for line in self.readfile(f):
                i = i + 1
                if i <= 2:
                    continue
                line = line.strip().split('-----')
                self.q.put(line)

    def comparefeature(self):
        while not self.q.empty():
            content = self.q.get()
            response = self.requests(self.url + content[0])
            #print(response)
            if re.search(content[1], str(response)):
                self.knew = self.knew + 1
                print(self.knew)
                if self.knew >= 3:
                    print('[*]Based on feature: ', content[2])
                    os._exit(0)

    def run(self):
        print('[-]Start scanning what cms')
        self.compareico()
        self.getfeature()
        for i in range(self.threads):
            t = threading.Thread(target=self.comparefeature)
            t.setDaemon(True)
            t.start()
        
        self.q.join()

        if not self.isknow:
            print('[-]Based feature: Unknown')


if __name__ == '__main__':
    cms = cmsscan('http://slradio.net/')
    cms.run()

