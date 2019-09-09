# -*- coding:utf-8 -*-
import requests,time
import sys

def file_scan(url):
    f = open("filedb.txt","r")
    files = f.read().split("\n")
    for i in files:
        nurl = url+i
        try:
            c = requests.get(nurl).content
            #print(c)
            if "404" in str(c):
                print(nurl + " : 404")
            else:
                print(nurl + " : exist")
        except:
            print(sys.exc_info()[0])
        
        time.sleep(1)
        

if __name__ == '__main__':
    file_scan("http://206.189.66.152/")
