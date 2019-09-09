# -*- coding:utf-8 -*-
__author__ = '1ABlades'

from optparse import OptionParser
import sys
from imp import reload
import requests
import json
from filescan import file_scan
import filescan
from portscan import portscan
from cmsscan import cmsscan

reload(sys)
#sys.setdefaultencoding('utf-8')          #设置编码
def cms_identifi():
    url = input("请输入url地址：", "utf-8").encode("gbk")
    headers={
		'Content-Type':'application/x-www-form-urlencoded'
	}
    post={
		'hash':'0eca8914342fc63f5a2ef5246b7a3b14_7289fd8cf7f420f594ac165e475f1479',
		'url':url
	
	

    }



if __name__ == '__main__':
    print('''
/////////////////////////////////////////////////////////////////////
                    ++++++++++++
                    ++++++++++++++++++
                ++++++++++++++++++++++
                ++++++++++++++++++++++++ + ++++
                ++++++++++++++++++++++++ +++ ++++++
                ++++++++++++++++++++++++++++++++++++
                ++++++++++++++++++++++++++++++++++++
                :::::::::,a@@a,:::::,a@a,++++++++++.
            .ooOOOOOOOOOOo@@@@@@oOoOo@@@@2@,++++++++/:.
        o OOOOOOOOOOOOo@@@@@@@@@oOOo@@@@@@,++++++/:::
    o oOOOOOOOOOOOOOo@@@@@@@@@@@oOo@@@@@@a  ':::::::
    oOoOOOOOOOOOOOOOOo@@@@@@@@@@@oOo@@@@@@@   :::::::
    oOOOOOOOOOOOOOOOOo@@@@@@@@@@@@oOo@@@@@@@   ::: ::'
    oOOOOOOOOOOOOOOOOo`  '@@@@@@@@oOo` '@@@@  ,:'  '
    oOOOOOOO%%%%%OOOOo    @@@@@@@@oOo   @@@a
    oOOOO;%%%.%%%OOOo.  ,@@@@@@@oOOo. ,@@@'
    oOOO%%%.%%%%%OOOoa@@@@@@@@oOOOo@@@@@'
    OOO%%%.%%%%%%OOo@@@@@@@@oOOOOOo@@@'        .,;%%%%%;.
        OOO%%.%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%//%%%%%%%%%
        OO%%.%%%%%%%%%%%%%%%%;%%%%%%%%%%%%%%//%%%%%%%%%%%;
            O%%.....';%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%;'
            %%.............%%%%%%%%%%%%%%%%%%%%%%%;'
            %%............`%%,   """""""""""""
                %%............%%;
                %%...........%%;
                %%%%%%%%%%%%%;
                `%%%%%%%%%;'

/////////////////////////////////////////////////////////////////////

1.web sensitive directory scan
2.cms identify
3.live machine scan and port service scan

    ''')

    flag = input("[-]input number: ")
    if flag == '1':
        url = input("[-]input your url: ")
        file_scan(url)
    
    elif flag == '2':
        url = input("[-]input your url: ")
        cms = cmsscan(url)
        cms.run()

    elif flag == '3':
        ip = input("[-]input your ip: ")
        ports = input("[-]input your ports: ")
        portscan = portscan(ports)
        portscan.run(1, 50, ip, 'result/res.txt')

    #print(flag)

'''
parser = OptionParser(description='ports&*weak password scanner.')
parser.add_option('--ip', dest='ip', type='string')
3
(options, args) = parser.parse_args()
ip = options.ip
filename = options.file
'''