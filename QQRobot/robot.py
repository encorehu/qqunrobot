#-*- coding:utf-8 -*-
from gevent import monkey;
import select
from gevent.socket import wait_read
monkey.patch_all()
from gevent.fileobject import FileObject
import urllib2
import urllib
import re
import time
import cookielib
import hashlib
import binascii
import base64
import os
import sys
import random
import json
#import thread
import threading
import Queue

from WebQQClient import WebQQClient
# 2012-6-6

'''
进行md5加密，并输出二进制值
'''
def md5hash(str):
    return hashlib.md5(str).digest()
'''
进行md5加密，并输出16进制值
'''
def hex_md5hash(str):
    return hashlib.md5(str).hexdigest().upper()
"""
由于提取的验证码2为文本字符串，因此要把文本字符串转换成原始的字符串。
本函数先把\x00\x00\x00\x00\x95\x22\xea\x8a切片成list如['00','00','00','00','95','22','ea','8a'],
然后遍历这个list，对每个字符串进行转换，转换成16进制的数字，
最后使用chr函数，把16进制的数字转换成原始字符，并合并
"""
def hexchar2bin(uin):
    uin_final = ''
    uin = uin.split('\\x')
    for i in uin[1:]:
        uin_final += chr(int(i, 16))
        #print 'uin_final',uin_final
    return uin_final

def get_password(password, verifyCode1, verifyCode2):
    """
    根据明文密码计算出加密后的密码
    """
    password_1 = md5hash(password) #第一步，计算出来原始密码的MD5值，输出二进制
    password_2 = hex_md5hash(password_1 + hexchar2bin(verifyCode2)) #第二步，合并第二步产生的bin值与验证码2的bin值，并进行md5加密，输出32位的16进制
    password_final = hex_md5hash(password_2 + verifyCode1.upper()) #第三步，合并第二步产生的16进制值与验证码1，并进行md5加密，输出32位的16进制值
    return password_final

def get_username(username):
    return base64.encodestring(urllib.quote(username))[:-1]


def get_timestamp():
    return ('%0.3f' % time.time()).replace('.','')



ONLINE  = 1
OFFLINE = 0
HIDEME  = 2


def InitQQThread():
    webqq= WebQQClient('1851038450','u7654321')
    print dir(webqq)

    if webqq.login():
        print u'获取自己的信息'
        print webqq.get_self_info2()

        print u'获取自己的QQ签名'
        print webqq.get_single_long_nick2()

        print u'获取自己的朋友列表'
        print webqq.get_user_friends2()

        print u'获取自己的群列表'
        print webqq.get_group_list()
        webqq.Start()
        return webqq

        '''print u'在朋友列表中找好友糊糊, 然后给他发个随机消息'
        for friend in webqq.friends:
            if friend['nick'] == u'糊糊':
                uin = friend['uin']
                msg = '我上线了...' + str(time.time())
                print '给 %s, 发送消息: %s' %(uin,msg)
                print webqq.send_message(uin,msg) '''
def raw_input(message):
    """ Non-blocking input from stdin. """
    sys.stdout.write(message)
    #wait_read(sys.stdin.fileno())
    #select.select([sys.stdin], [], [])
    #wait_read(sys.stdin.fileno())

    #select.select([sys.stdin], [], [])
    return sys.stdin.readline()

if __name__ =='__main__':
    print 'Start WebQQunRobot...'
    webqq = InitQQThread()
    sys.stdin = FileObject(sys.stdin)
    while True:
        cmd = raw_input(">: ")
        print cmd
        if(cmd == 'login'):
            webqq.login()
        elif cmd == 'stop':
            webqq.Stop()
            #print 'login-----'
        #webqq.msgloop()
    '''else:
        print u'机器人登录失败'
        print webqq.errors
        #webqq.poll('http://www.baidu.com/')'''
    #webqq.logout()
    print 'Quit WebQQunRobot'






"""
其他接口
获取头像
http://face7.qun.qq.com/cgi/svr/face/getface?cache=0&type=1&fid=0&uin=号码

获取个人信息
http://web2-b.qq.com/api/get_single_info?tuin=qq号码
获取签名
http://web2-b.qq.com/api/get_single_long_nick?tuin=qq号码&t=1288751545148
获取好友列表
http://web2-b.qq.com/api/get_user_friends
r    {"vfwebqq":"8f1383ba2239bb7295b100af215274aff1ee4be177b467cbc386fc53ff6606a8e5941aca61d0eb51"}
获取在线的qq好友
http://web2-b.qq.com/channel/get_online_buddies?clientid=9547083&psessionid=8368046764001D636F6E6E7365727665725F77656271714031302E3133332E332E323430000062F000000B86026E040043F60C166D0000000A404F526B7558357668476D000000288F1383BA2239BB7295B100AF215274AFF1EE4BE177B467CBC386FC53FF6606A8E5941ACA61D0EB51&t=1288751548600
获取最近联系人
http://web2-b.qq.com/api/get_recent_contact
r    {"vfwebqq":"8f1383ba2239bb7295b100af215274aff1ee4be177b467cbc386fc53ff6606a8e5941aca61d0eb51"}
"""
