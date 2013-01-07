#-*- coding:utf-8 -*-
from gevent import monkey;
import select
from gevent.socket import wait_read
monkey.patch_all()
from gevent.fileobject import FileObject
import sys

from WebQQClient import WebQQClient

def InitQQThread():
    webqq= WebQQClient('12345678','u7654321')
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

def raw_input(message):
    """ Non-blocking input from stdin. """
    sys.stdout.write(message)
    #wait_read(sys.stdin.fileno())
    #select.select([sys.stdin], [], [])
    #wait_read(sys.stdin.fileno())

    #select.select([sys.stdin], [], [])
    return sys.stdin.readline()

if __name__ =='__main__':
    print 'Starting WebQQunRobot...'
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
