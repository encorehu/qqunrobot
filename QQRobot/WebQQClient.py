# -*- coding: utf-8 -*-
from gevent import monkey
from gevent.timeout import Timeout
import gevent
monkey.patch_all(dns=False, thread=False)
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
import threading
import Queue
import socket
from MsgHandler import MsgHandler
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

class WebQQClient(threading.Thread):
    WEBQQ_APPID     = 1003903
    WEBQQ_VERSION   = 'WebQQ3.0'

    name        = 'WebQQClient for WebQQ3.0, Python Version'
    version     = '0.1'
    author      = 'HUHU,huyoo353@126.com'
    createtime  = '2012-12-30 22:00:00'
    releasetime = '2012-12-30 22:00:00'

    cookiefile  = '0.txt'
    datapath    = './data'
    configfile  = 'config.json'
    cookie      = None
    opener      = None # 这个就像一个浏览器

    # msg reply settings
    reply_qun_msg    = True #回复群消息
    reply_friend_msg = True #回复好友消息
    reply_temp_msg   = True #回复临时会话消息

    # 消息处理器, 用于从插件中加载消息处理器
    # 即,接收到消息之后如何处理
    # (处理器名称, 启用状态=on|off, 处理方法)
    message_handlers = []

    # 机器人接收到的消息
    flag = 1

    msg_queue   = None # Queue.Queue() #  接收到的消息队列, 即未处理消息, 格式为json对象, 并且每个对象的格式并不完全一致
    handled_msgs = None # Queue.Queue() #  已经处理了的消息 格式同样为json 的队列

    msg_poller  = None
    msg_handler = None

    errors = []
    msgid  = ''
    sleep_time = 0.5 # 休眠500毫秒,0.5秒

    # 机器人的联系人信息
    friends    = []
    group_list = []

    clientid  = 92963676
    logged_in = False

    # 登录web.qq.com的返回cookie中的值, 用于后面登录qq聊天接口

    ptwebqq    = ''
    skey       = ''
    ptcz       = ''
    # 登录qq聊天接口返回的cookie中的值, 用于后续获取用户列表和群列表, 发言等等功能
    vfwebqq    = ''
    psessionid = ''




    # 连接配置
    timeout = 6 # 一分钟
    headers = { 'User-agent': 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.84 Safari/535.11 SE 2.X MetaSr 1.0'}


    filepath    = os.path.normpath(os.path.dirname(sys.argv[0]))

    def __init__(self,uin,password=None,mode='online'):
        threading.Thread.__init__(self)
        if str.isdigit(uin) == False:
            raise Exception('You must input correct QQ number, must be numeric.')

        self.uin      = uin
        self.password = password
        self.mode     = mode
        self.verifyCode1 = ''
        self.verifyCode2 = ''

        if not os.path.exists(self.datapath):
            os.makedirs(self.datapath)
        self.cookiefile   = os.path.join(self.datapath, 'cookie_%s@webqq.txt' % uin).replace('\\','/')
        print self.cookiefile

        self.cookie = self.load_cookie()
        """
        构建一个全局通用的opener，全程自动保存并使用cookies
        """
        self.opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(self.cookie))
        self.opener.addheaders = self.headers.items()

        urllib2.install_opener(self.opener)

        if not self.clientid:
            self.clientid = str(random.random())[2:10] # 客户端clientid 取8位随机数, 只取这一次就够了, 全程保持统一, 注销的时候消掉

        ff=open('flag.txt','w')
        ff.write('flag=1')
        ff.close()
        self.msg_queue  = Queue.Queue()

    def __del__(self):
        print '机器人销毁自己'

    def Stop(self):
        msg={};
        msg['poll_type'] = 'robotquit'
        self.msg_queue.put(msg)
        self.flag=0
        self.join()
        print 'join ok'

    def load_cookie(self,update=False):
        print '开始加载qqapi重要配置数据'
        ff=open(self.configfile,'r')
        text = ff.read()
        ff.close()

        try:
            config=json.loads(text)
            try:
                self.vfwebqq    = config['vfwebqq']
                self.psessionid = config['psessionid']
                self.clientid   = config['clientid']
            except KeyError:
                self.vfwebqq    = ''
                self.psessionid = ''
                self.clientid   = 0
        except ValueError:
            pass
        print 'vfwebqq',    self.vfwebqq
        print 'psessionid', self.psessionid
        print 'clientid',   self.clientid

        print '开始加载cookie'
        cookies = cookielib.MozillaCookieJar(self.cookiefile)

        try:
            """加载已存在的cookie，尝试此cookie是否还有效"""
            cookies.load(ignore_discard=True, ignore_expires=True)
            if not update:
                return cookies
        except Exception, e:
            """加载失败，说明从未登录过，需创建一个空的 cookie 文件"""
            cookies.save(self.cookiefile, ignore_discard=True, ignore_expires=True)
            return cookies


    def save_cookie(self):
        """
        保存成功的cookie到文件中去，以便于不会频繁登陆
        再看看返回的COOKIES，一共2个，分别是ptvfsession和confirmuin,他们的值比较的长：
        pt2gguin=o1213200914; pgv_pvid=190953684; pgv_r_cookie=123523467483; o_cookie=1213200914;
        ac=1,019,001; ptui_loginuin=1213200914; RK=9E7jFqpSSn; __hash__=039123164953aed1fd3eab5c1ef2f488;
        pgv_flv=10.0; pgv_pvi=9975191567; pgv_info=pgvReferrer=&ssid=s4369498920;
        ptcz=f606be77d7a2b4b52b25dd0e39caf1f5f2652d8efff92e934f7830a7d270dc70; chkuin=1213200914
        COOKIES都要留着，在之后登陆提交时，需要附上！
        """
        print '保存cookie到文件'
        self.cookie.save(self.cookiefile, ignore_discard=True, ignore_expires=True)

        print '保存重要数据到配置文件'
        ff=open(self.configfile,'w')
        ff.write(json.dumps({'psessionid':self.psessionid,'vfwebqq':self.vfwebqq,'clientid':self.clientid}).encode('utf-8'))
        ff.close()



    def need_password(self):
        if self.password is None or len(self.password)<8 :
            return True
        else:
            return False

    def need_verify_image(self):
        # 在登录之前的准备
        if self.need_password():
            password = raw_input("Your Password is invalid, Please input the password for QQ(%s):" % self.uin)
            if password.strip():
                self.password = password.strip()
            else:
                print 'You input NOTHING, quit.'
                self.errors.append({'func::need_verify_image':'Password is None'})
                return False

        print u'1.开始检查是否需要输入验证码'
        """
        算出用户名加密后的字符串
        """
        verifyURL = 'http://check.ptlogin2.qq.com/check?uin=%s&appid=%s&r=%s' % (self.uin, self.WEBQQ_APPID, random.random())
        self.headers['Host'] = 'ptlogin2.qq.com'
        self.headers['Connection'] = 'keep-alive'
        self.opener.addheaders = self.headers.items()
        """
        获取初次加密所需要的一个关键参数值
        """
        #print 'GET ',verifyURL
        response = self.opener.open(verifyURL)
        #print 'REALURL',
        #print response.geturl()
        print response.info()
        """
        对response的文本进行提取，第一步拆分成["ptui_checkVC('0'", "'!YQL'", " '\\x00\\x00\\x00\\x00\\x95\\x22\\xea\\x8a');"]
        """
        content = response.read()
        print content
        self.save_cookie()
        # ptui_checkVC('0','!T23','\x00\x00\x00\x00\x01\xe4\xfa\x78');

        content=content.split(',')
        """
        提取用于生成加密后的密码的验证字符串1——!YQL 长度一般为4, 如果大于4, 说明需要验证码
        """
        self.verifyCode1 = content[1][1:-1]
        print 'verifyCode1',self.verifyCode1
        """
        提取用于生成加密后的密码的验证字符串2——\x00\x00\x00\x00\x95\x22\xea\x8a
        是我们QQ号码的16进制形式， QQ号为：1213200914（我的qq），
        我们把\x00\x00\x00\x00\x48\x4f\xfa\x12中的\\x去掉之后就剩下484ffa12,
        我们用计算器转换一下这个数为10进制，便是1213200914
        """
        self.verifyCode2 = content[2].split("'")[1]
        print 'verifyCode2',self.verifyCode2

        """
        判断是否出现图片验证码，这里为了图方便判断验证码1是否是4位，不是则为出现图片验证码。其实更好的方法是判断ptui_checkVC('0'"，如果是0，则是文字验证，如果是1则为图片验证
        """
        if len(self.verifyCode1) > 4:
            # 获取验证码图片 http://captcha.qq.com/getimage?aid=1003903&&uin=qq号码&vc_type=verifyCode2
            # 这里不处理验证码的问题
            print 'Your QQ need capcha to login.'
            return True
        else:
            print '不需要输入验证码, 可以进行下一步登录webqqcom了.'
            return False

    def need_login_webqqcom(self):
        # 看看 这个机器人还需不需要再次登录http://web.qq.com
        # ptwebqq 的值是未注销之前的值, 如果有值, 说明cookie或者内存中有这个值, 机器人还处于未注销的状态, 就不需要再次登录网站了
        if self.cookie == None:
            return True
        else:
            for index,cookie in enumerate(self.cookie):
                #print index,":",cookie
                if cookie.name == 'ptwebqq':
                    self.ptwebqq = cookie.value

                if cookie.name == 'skey':
                    self.skey    = cookie.value

                if cookie.name == 'ptcz':
                    self.ptcz    = cookie.value

            if self.ptwebqq:
                return False
            else:
                return True

    def need_login_qqapi(self):
        # 看看 这个机器人还需不需要再次登录http://web.qq.com
        # ptwebqq 的值是未注销之前的值, 如果有值, 说明cookie或者内存中有这个值, 机器人还处于未注销的状态, 就不需要再次登录网站了
        print 'vfwebqq',repr(self.vfwebqq)
        print 'psessionid',repr(self.psessionid)
        print 'Boolean', repr(self.vfwebqq and self.psessionid)
        if self.vfwebqq =='' and self.psessionid =='':
            print u'qqapi接口重要参数是空值!!!!!需要获取这些重要参数'
            return True
        else:
            print u'qqapi接口重要参数是:',self.vfwebqq, self.psessionid
            return False

    def login_webqqcom(self):
        """
        根据获取到的验证码1与验证码2对密码进行加密处理，并组合生成登陆的url
        http://ptlogin2.qq.com/login?u=qq号码&p=密码和验证码加密后的字符串&verifycode=验 证码&remember_uin=1&aid=1003903&u1=http%3A%2F%2Fweb2.qq.com%2Floginproxy.html%3Fstrong%3Dtrue&h=1&ptredirect=0&ptlang=2052&from_ui=1&pttype=1&dumy=&fp=loginerroralert
        req = urllib2.Request(loginURL)
        /login?
        u=2484810628
        &p=加密串
        &verifycode=!3WL
        &webqq_type=10
        &remember_uin=1
        &login2qq=0
        &aid=1003903
        &u1=http%3A%2F%2Fweb.qq.com%2Floginproxy.html%3Flogin2qq%3D0%26webqq_type%3D10
        &h=1
        &ptredirect=0
        &ptlang=2052
        &from_ui=1
        &pttype=1
        &dumy=
        &fp=loginerroralert
        &action=5-25-61202
        &mibao_css=m_webqq
        &t=1
        &g=1
        &js_type=0
        &js_ver=10014
        &login_sig=VVnaX8LN75LvhxLVtUJdWyqLlnzbAuioH*NxlMV2IrOfmKzES0-WoD-1sjBA6Y5z
        """
        print u'2.开始登录webqq网站'
        loginURL  = 'http://ptlogin2.qq.com/login?'
        #loginURL += "u=%s&p=" % self.uin
        #loginURL += get_password(self.password, verifyCode1, verifyCode2) #对密码进行加密
        #loginURL += "&verifycode=" + verifyCode1 + "&remember_uin=1&aid=1003903&u1=http%3A%2F%2Fweb2.qq.com%2Floginproxy.html%3Fstrong%3Dtrue&h=1&ptredirect=0&ptlang=2052&from_ui=1&pttype=1&dumy=&fp=loginerroralert"
        #以上几句和后面的重复之后, 居然cookie都不能正常获取了, 注释了就好了.

        data ={
            'u':self.uin,
            'p':get_password(self.password, self.verifyCode1, self.verifyCode2), #对密码进行加密
            'verifycode':self.verifyCode1,
            'webqq_type':'10',
            'remember_uin':1,
            'login2qq':'0',# 有的人是1
            'aid':1003903,
            'u1':'http://web.qq.com/loginproxy.html?login2qq=0&webqq_type=10',
            'strong':'true',
            'h':'1',
            'ptredirect':'0',
            'ptlang':'2052',
            'from_ui':'1',
            'pttype':'1',
            'dumy':'',
            'fp':'loginerroralert',
            't':'1',
            'g':'1',
            'action':'5-25-61202',
            'mibao_css':'m_webqq',
            }

        query_string = urllib.urlencode(data)
        #print 'query_string',query_string

        loginURL=loginURL+query_string
        print 'GET ',loginURL
        """
        添加http的header头，一定要添加referer,腾讯服务器会判断, 否则登录不成功
        """
        #self.headers['Referer'] = 'http://web2-b.qq.com/proxy.html'
        self.headers['Referer'] = 'http://ui.ptlogin2.qq.com/cgi-bin/login?target=self&style=5&mibao_css=m_webqq&appid=1003903&enable_qlogin=0&no_verifyimg=1&s_url=http%3A%2F%2Fweb.qq.com%2Floginproxy.html&f_url=loginerroralert&strong_login=0&login_state=10&t=20121029001'
        self.headers['Connection'] = 'keep-alive'

        self.opener.addheaders = self.headers.items()
        """
        获取登录令牌第一部分，如果要写的健壮一些，那么这里可以对返回数据做一个验证，
        正常登陆返回ptuiCB('0','0','http://t.qq.com','1','登录成功！', '娱讯传媒');
        可以验证第一个0，如果不是0，那么就是不正常登陆
        """
        response=self.opener.open(loginURL)
        print 'REALURL',
        print response.geturl()
        print response.info()

        content = response.read()
        print content
        self.save_cookie()

        print u'2.1 检查cookie中的数据'
        #print self.cookie.make_cookies()
        for index,cookie in enumerate(self.cookie):
            #print index,":",cookie
            if cookie.name == 'ptwebqq':
                self.ptwebqq = cookie.value

            if cookie.name == 'skey':
                self.skey    = cookie.value

            if cookie.name == 'ptcz':
                self.ptcz    = cookie.value
                #if index ==1:
            #    gsid = cookie.value
            print cookie.name,cookie.value #,cookie.port,cookie.path,cookie.expires

        if self.skey == '' :
            print u'虽然登录了webqqcom, 但是没有接收到下一步中必须用到的几个cookie'
            self.logged_in = False
            return False
        else:
            print u'成功登录了webqqcom, 并同时获取到了下一步中必须用到的几个cookie'
            self.logged_in = True
            return True

            #self.ptwebqq = self.cookie.get('ptwebqq','')
            #self.skey    = self.cookie.get('skey','')

    def login_qqapi(self):
        """ webQQ登录流程
        1. 输入框中输入QQ号码之后, 点击密码框的时候, 会触发 请求验证码 事件,访问http://check.ptlogin2.qq.com/ 看看你的账号是否异常, 如果正常就不需要验证码
        2. 对输入的密码进行加密后, 提供QQ号码, 加密后的密码到'http://ptlogin2.qq.com/login?' 进行验证登录, 这个时候只是相当于登录了web.qq.com这个网站
        3. 登录qq. 根据第二步中的返回结果, 得到加密的字符串, 访问  最终登录了QQ.
        """



        """http://d.web2.qq.com/channel/login2
        访问qq真实登录地址，获取登录令牌第二部分——最后补全的cookies,如果不能获取，则代表登录出现问题

        提交数据 ＝ “r=%7B%22status%22%3A%22online%22%2C%22ptwebqq%22%3A%22” ＋ ptwebqq ＋ “%22%2C%22passwd_sig%22%3A%22%22%2C%22clientid%22%3A%22” ＋ clintid ＋ “%22%2C%22psessionid%22%3Anull%7D&clientid=” ＋ clintid ＋ “&psessionid=null”

        """
        #print self.cookie
        print u'3.登录qq聊天接口'
        #login_url2 = 'http://web2-b.qq.com/channel/login'
        #self.headers['Referer'] = 'http://web2-b.qq.com/proxy.html'

        login_url2 = 'http://d.web2.qq.com/channel/login2'
        self.headers['Referer'] = 'http://d.web2.qq.com/proxy.html?v=20110331002&callback=1&id=3'
        #print 'POST', login_url2

        #登陆成功之后, 浏览器用的地址, 实际上程序用不着
        #login_url2 = 'http://web.qq.com/loginproxy.html?login2qq=0&webqq_type=10'
        #print 'GET', login_url2
        #self.headers['Referer'] = 'http://ui.ptlogin2.qq.com/cgi-bin/login?target=self&style=5&mibao_css=m_webqq&appid=1003903&enable_qlogin=0&no_verifyimg=1&s_url=http%3A%2F%2Fweb.qq.com%2Floginproxy.html&f_url=loginerroralert&strong_login=0&login_state=10&t=20121029001'


        self.opener.addheaders = self.headers.items()

        #post_data = 'r={"status":"","ptwebqq":"%s","passwd_sig":"","clientid":"97923442"}' % self.ptwebqq
        post_data = 'r={"status":"online","ptwebqq":"%s","passwd_sig":"","clientid":"%s","psessionid":null}&clientid=%s&psessionid=null' % (self.ptwebqq,self.clientid,self.clientid)
        #print post_data

        """ 'r={"status":"","ptwebqq":"{1}","passwd_sig":"","clientid":"{2}"}' """
        post_data = urllib.quote(post_data,safe='=')



        """
        获得完整的登录令牌
        """
        #post_data = urllib.urlencode(post_data)
        #response = self.opener.open(login_url2, post_data, self.timeout )
        response = self.opener.open(login_url2, post_data, self.timeout )
        #print 'REALURL',
        #print response.geturl()
        #print response.info()

        content  = response.read()
        #print content

        #
        #print 'Cookies..........'
        #for index,cookie in enumerate(self.cookie):
        #    #print index,":",cookie
        #    print cookie.name, cookie.value

        json_data = json.loads(content,encoding='utf-8')
        # 获取 vfwebqq 和 psessionid
        retcode = json_data['retcode']
        if retcode == 0:
            print u'正常登录qqapi接口'
            try:
                print u'从返回的数据中获取用于操作 qqapi 接口的必要信息'
                self.vfwebqq    = json_data['result']['vfwebqq']
                self.psessionid = json_data['result']['psessionid']
                self.save_cookie()
                print u'重要信息获取成功'
                return True
            except KeyError:
                self.vfwebqq    = ''
                self.psessionid = ''
                print '未能正常获取用于操作 qqapi 接口的必要信息, 登录失败.'
                return False
        elif  retcode == 103 or retcode ==121:
            print u'连接不成功，需要重新登录'
            self.logged_in = False
            return False

    def login(self):
        if not self.need_login_webqqcom():
            print u'无需登录webqqcom, 直接使用现有session数据登录qqapi接口'
            if not self.need_login_qqapi(): # 不需要登录 qqapi了, 这表示登录成功, 以后可以发消息 获取用户信息等操作了
                print '操作qqapi的重要参数已经获取, 不需要重新登录qqapi接口'
                return True
            else: #webqqcom 登录之后的检查参数
                print u'操作qqapi的重要参数还未获取, 需要继续登录qqapi接口'
                print u'登录qqapi接口...'
                if self.login_qqapi():
                    print u'成功登陆qqapi接口!'
                    return True
                else:
                    print '本地session可能过期, 将尝试从webqqcom开始登录...'
                    result = False
                    if not self.need_verify_image():
                        if self.login_webqqcom():
                            result = self.login_qqapi()
                    return result
        else:#不需要登录 webqqcom, 直接去登录 qqapi 接口
            print u'需要登录webqqcom'
            if not self.need_verify_image():
                if not self.login_webqqcom():
                    print u'登录qqwebcom失败'
                    return False
                else:
                    print u'登录webqqcom成功, 开始登录qqapi接口...'
                    return self.login_qqapi()
            else:
                print u'需要获取图片验证码之后,才能继续登录, 现在这个没有处理, 直接返回登录失败'
                return False


    def logout(self):
        api_url   = 'http://d.web2.qq.com/channel/logout2?ids=&clientid=%s&psessionid=%s&t=%s' % (self.clientid, self.psessionid, get_timestamp())
        post_data = None

        self.headers['Referer'] = 'http://d.web2.qq.com/proxy.html?v=20110331002&callback=1&id=3'
        self.opener.addheaders = self.headers.items()

        response = self.opener.open(api_url,post_data,self.timeout)
        content  = response.read()
        print '%s logout...' % self.uin
        print content
        self.vfwebqq    = ''
        self.psessionid = ''
        self.clientid   = 0

        self.save_cookie()

    def get_self_info2(self):
        api_url   = 'http://s.web2.qq.com/api/get_self_info2?t=%s' % get_timestamp()
        if self.vfwebqq:
            post_data = 'r={"h":"hello","vfwebqq":"%s"}' % self.vfwebqq
            post_data = urllib.quote(post_data,safe='=')
            response = self.opener.open(api_url,post_data,self.timeout)
            content  = response.read()
            '''
            {"retcode":0,
            "result":{
                "birthday":{"month":1,"year":1986,"day":1},
                "face":555,"phone":"","occupation":"","allow":1,"college":"",
                "uin":2484810628,"blood":0,"constel":12,"lnick":"",
                "vfwebqq":"...",
                "homepage":"","vip_info":0,"city":"长沙","country":"中国","personal":"","shengxiao":2,
                "nick":"贱狗巴弟","email":"","province":"湖南","account":2484810628,"gender":"male","mobile":""}}
            '''
            json_data = json.loads(content,encoding='utf-8')
            try:
                self.nick = json_data['result']['nick']
                print u'%s(%s)' % (json_data['result']['nick'], json_data['result']['account'])
            except KeyError:
                self.nick = ''
            print self.nick

            return json_data
        else:
            return None

    def get_online_buddies2(self):
        api_url   = 'http://s.web2.qq.com/api/get_online_buddies2?clientid=%s&psessionid=%s' % (self.clientid, self.psessionid)
        if self.vfwebqq:
            post_data = 'r={"h":"hello","vfwebqq":"%s"}' % self.vfwebqq
            post_data = urllib.quote(post_data,safe='=')
            response = self.opener.open(api_url,post_data,self.timeout)
            content  = response.read()
            '''
            {"retcode":0,
            "result":{
                "birthday":{"month":1,"year":1986,"day":1},
                "face":555,"phone":"","occupation":"","allow":1,"college":"",
                "uin":2484810628,"blood":0,"constel":12,"lnick":"",
                "vfwebqq":"...",
                "homepage":"","vip_info":0,"city":"长沙","country":"中国","personal":"","shengxiao":2,
                "nick":"贱狗巴弟","email":"","province":"湖南","account":2484810628,"gender":"male","mobile":""}}
            '''
            json_data = json.loads(content,encoding='utf-8')
            try:
                self.nick = json_data['result']['nick']
            except KeyError:
                self.nick = ''
            print self.nick

            return json_data
        else:
            return None

    def get_user_friends(self):
        #r=%7B%22h%22%3A%22hello%22%2C%22vfwebqq%22%3A%221d27e29737b337354ab767654cfac8c1c75163ecc65639e81b1f4d19a0c308e7982f27cb2c1e0f55%22%7D
        api_url   = 'http://s.web2.qq.com/api/get_user_friends'
        if self.vfwebqq:
            post_data = 'r={"h":"hello","vfwebqq":"%s"}' % self.vfwebqq
            post_data = urllib.quote(post_data,safe='=')
            response = self.opener.open(api_url,post_data,self.timeout)
            content  = response.read()
            '''
            {"retcode":0,"result":{
            "friends":[
                {"flag":0,"uin":3824933956,"categories":0},
                {"flag":0,"uin":3113307908,"categories":0}
            ],
            "marknames":[],
            "categories":[{"index":1,"sort":1,"name":"朋友"},{"index":2,"sort":2,"name":"家人"},{"index":3,"sort":3,"name":"同学"}],
            "vipinfo":[{"vip_level":0,"u":3824933956,"is_vip":0},{"vip_level":0,"u":3113307908,"is_vip":0}],
            "info":[
                {"face":261,"flag":524802,"nick":"小明","uin":3824933956},
                {"face":606,"flag":4227584,"nick":"糊糊","uin":3113307908}
                ]}}
            '''
            json_data = json.loads(content,encoding='utf-8')
            try:
                self.friends=  json_data['result']['info']
            except KeyError:
                self.friends = []
            for f in self.friends:
                print f['nick'], f['uin']

            return json_data
        else:
            return None

    def get_user_friends2(self):
        #r=%7B%22h%22%3A%22hello%22%2C%22vfwebqq%22%3A%221d27e29737b337354ab767654cfac8c1c75163ecc65639e81b1f4d19a0c308e7982f27cb2c1e0f55%22%7D
        api_url   = 'http://s.web2.qq.com/api/get_user_friends2'
        if self.vfwebqq:
            post_data = 'r={"h":"hello","vfwebqq":"%s"}' % self.vfwebqq
            post_data = urllib.quote(post_data,safe='=')
            response = self.opener.open(api_url,post_data,self.timeout)
            content  = response.read()
            '''
            {"retcode":0,"result":{
            "friends":[
                {"flag":0,"uin":3824933956,"categories":0},
                {"flag":0,"uin":3113307908,"categories":0}
            ],
            "marknames":[],
            "categories":[{"index":1,"sort":1,"name":"朋友"},{"index":2,"sort":2,"name":"家人"},{"index":3,"sort":3,"name":"同学"}],
            "vipinfo":[{"vip_level":0,"u":3824933956,"is_vip":0},{"vip_level":0,"u":3113307908,"is_vip":0}],
            "info":[
                {"face":261,"flag":524802,"nick":"小明","uin":3824933956},
                {"face":606,"flag":4227584,"nick":"糊糊","uin":3113307908}
                ]}}
            '''
            json_data = json.loads(content,encoding='utf-8')
            try:
                self.friends=  json_data['result']['info']
            except KeyError:
                self.friends = []
            for f in self.friends:
                print f['nick'], f['uin']

            return json_data
        else:
            return None

    def get_group_list(self):
        #r=%7B%22h%22%3A%22hello%22%2C%22vfwebqq%22%3A%221d27e29737b337354ab767654cfac8c1c75163ecc65639e81b1f4d19a0c308e7982f27cb2c1e0f55%22%7D
        api_url   = 'http://s.web2.qq.com/api/get_group_name_list_mask2'
        if self.vfwebqq:
            post_data = 'r={"vfwebqq":"%s"}' % self.vfwebqq
            post_data = urllib.quote(post_data,safe='=')
            #post_data = None
            response = self.opener.open(api_url,post_data,self.timeout)
            content  = response.read()
            return content
        else:
            return None

    def get_single_long_nick2(self):
        # 获取机器人的QQ签名
        if self.vfwebqq:
            api_url = 'http://s.web2.qq.com/api/get_single_long_nick2?tuin=%s&vfwebqq=%s&t=%s' % (self.uin, self.vfwebqq, time.time() )
            post_data = 'r={"h":"hello","vfwebqq":"%s"}' % self.vfwebqq
            post_data = urllib.quote(post_data,safe='=')
            post_data = None
            response = self.opener.open(api_url,post_data,self.timeout)
            content  = response.read()

            self.lnick = ''
            try:
                json_data = json.loads(content)
                try:
                    self.lnick = json_data['result'][0]['lnick']
                except KeyError:
                    pass
            except ValueError:
                pass
            print 'lnick', self.lnick
            return self.lnick

        else:
            return None
    def print_head(self,api_url,post_data):
        #print 'Starting %s' % url
        #data = urllib2.urlopen(url).read()
        try:
            response = self.opener.open(api_url,post_data,self.timeout)
            content  = response.read()
        except urllib2.HTTPError,e:
            self.last_poll_retcode = 109
            print u'连接到服务器发生错误.',e
            content = ''
        except urllib2.socket.timeout, e:
            print 'Timeout!',e
            self.last_poll_retcode = 109
            content = ''

    def poll3(self):
        api_url = 'http://d.web2.qq.com/channel/poll2'
        refer   = 'http://d.web2.qq.com/proxy.html?v=20110331002&callback=1&id=3'
        """
        'r={"clientid":"58472589","psessionid":"...","key":0,"ids":["51500","51501","51502","51503","51504","51505","51506","51507","51508","51509","51510","51511","51512","51513","51514","51515","51516","51517","51518","51519"]}
        &clientid=58472589&psessionid=...'
        """
        data = {'clientid':self.clientid,'psessionid':self.psessionid,'key':0,'ids':[]}
        data2 = { 'r':json.dumps(data),'clientid':self.clientid,'psessionid':self.psessionid }
        post_data = urllib.urlencode(data2)


        self.headers['Referer'] = refer
        self.opener.addheaders = self.headers.items()
        #jobs = [gevent.spawn(print_head, url) for url in urls]
        #jobs=[gevent.spawn(self.print_head, api_url,post_data)]
        #jobs.join()
        #gevent.joinall(jobs)
        try:
            response = self.opener.open(api_url,post_data,self.timeout)
            #print 'REALURL',
            #print response.geturl()
            #print response.info()
            content  = response.read()
            #不出意外，这是返回结果：{"retcode":0,"result":"..."}
        except urllib2.HTTPError,e:
            self.last_poll_retcode = 109
            print u'连接到服务器发生错误.',e
            content = ''
        except urllib2.socket.timeout, e:
            print 'Timeout!',e
            self.last_poll_retcode = 109
            content = ''
        #连接建立，接收服务器端消息
        #print content # {"retcode":0, "result":xxxx}

        msg_result = []

        if content =='':
            return msg_result

        try:
            json_data  = json.loads(content)
            try:
                self.last_poll_retcode =  json_data['retcode']
                print 'retcode',  json_data['retcode'] # 如果不出毛病 retcode通常是0
                msg_result = json_data['result'] # 实际上是一个消息列表, 里面的消息格式各有不同
            except KeyError:
                pass
        except ValueError: # json.loads 失败
            pass

        return msg_result
    def get_msgid(self):
        if not self.msgid:
            self.msgid = str(random.randint(1000,9999)) + '0000'
        else:
            self.msgid = str(int(self.msgid)+1)
        return self.msgid

    def get_color(self):
        r=random.choice('1234567890abcdef')
        g=random.choice('1234567890abcdef')
        b=random.choice('1234567890abcdef')
        return r+r+g+g+b+b

    def send_message(self, uin, msg, msg_type=1, msg_id='', code=''):
        # msg_type：1-好友 2-群 3-临时
        #
        '''
        r={ "to":3844011912,
            "face":549,
            "content":"[,["font",{"name":"\xe5\xae\x8b\xe4\xbd\x93","size":"10","style":[0,0,0],"color":"000000"}]]",
            "msg_id":42130005,
            "clientid":"3213902",
            "psessionid":"..."
        }

        'r={"to":1083295010,"face":555,"content":"[\\"ceshi\\",\\"\\\\n\\",[\\"font\\",{\\"name\\":\\"\xe5\xae\x8b\xe4\xbd\x93\\",\\"size\\":\\"10\\",\\"style\\":[0,0,0],\\"color\\":\\"000000\\"}]]","msg_id":34720001,"clientid":"58472589","psessionid":"8368046764001e636f6e6e7365727665725f77656271714031302e3132382e36362e31313500005a99000015fa016e040084331b946d0000000a4070315031434e756d686d00000028e5d57f95b57ce587a75a8e8def8ac77b89d7a5bd04185c009ecd5610b9590b865bfcd97bd4aeec75"}&clientid=58472589&psessionid=8368046764001e636f6e6e7365727665725f77656271714031302e3132382e36362e31313500005a99000015fa016e040084331b946d0000000a4070315031434e756d686d00000028e5d57f95b57ce587a75a8e8def8ac77b89d7a5bd04185c009ecd5610b9590b865bfcd97bd4aeec75'
        '''
        #post_data = 'r={"to":3844011912,"face":549,"content":"[,["font",{"name":"\xe5\xae\x8b\xe4\xbd\x93","size":"10","style":[0,0,0],"color":"000000"}]]","msg_id":42130005,"clientid":"3213902","psessionid":"..."}' % self.ptwebqq
        api_url = 'http://d.web2.qq.com/channel/send_buddy_msg2'

        if self.psessionid:

            r={}
            r['to']   = uin
            r['face'] = 555
            content = []
            content.append(msg)
            content.append('\n【提示：此用户正在使用Q+ Web：http://web.qq.com/】')

            font = {
                'name':'宋体',
                'size':'10',
                'style':[0,0,0],
                'color':self.get_color()
            }

            content.append(['font',json.dumps(font)])


            r['content']    = json.dumps(content)
            r['msg_id']     = self.get_msgid()
            r['clientid']   = self.clientid
            r['psessionid'] = self.psessionid
            #print r
            #print repr(json.dumps(r))
            psessionid =  self.psessionid.encode('utf-8')
            msg = "[\""+ msg +"\",[\"font\",{\"name\":\"宋体\",\"size\":\"10\",\"style\":[0,0,0],\"color\":\"000000\"}]]"
            #for x in [uin, msg, self.get_color(), self.get_msgid(),self.clientid,self.psessionid,self.clientid,self.psessionid]:
            #    print x, type(x)
            data = {'to':uin,'face':180,'content':msg,'msg_id':self.get_msgid() ,'clientid':self.clientid,'psessionid':self.psessionid}
            data2 = {'r':json.dumps(data),'clientid':self.clientid,'psessionid':self.psessionid}


            #post_data = 'r={"to":%s,"face":555,"content":"[\\"%s\\",[\\"font\\",{\\"name\\":\\"\xe5\xae\x8b\xe4\xbd\x93\\",\\"size\\":\\"10\\",\\"style\\":[0,0,0],\\"color\\":\\"%s\\"}]]","msg_id":%s,"clientid":"%s","psessionid":"%s"}&clientid=%s&psessionid=%s' % (uin, msg, self.get_color(), self.get_msgid(),self.clientid, psessionid, self.clientid, psessionid)
            post_data = urllib.urlencode(data2)


            #post_data ='r=%s&clientid=%s&psessionid=%s' % (json.dumps(r), self.clientid, self.psessionid)
            #print data.replace(' ','')
            #print repr(data)
            #print '-'*66
            #print urllib.quote(data)
            print post_data
            #print repr(post_data)
            #post_data = urllib.quote(post_data)
            print '-'*66
            #print post_data


            self.headers['Referer'] = 'http://d.web2.qq.com/proxy.html?v=20110331002&callback=1&id=3'
            self.opener.addheaders = self.headers.items()
            """
            发消息
            'r={"to":1083295010,"face":555,"content":"[\\"ceshi\\",\\"\\\\n\xe3\x80\x90\xe6\x8f\x90\xe7\xa4\xba\xef\xbc\x9a\xe6\xad\xa4\xe7\x94\xa8\xe6\x88\xb7\xe6\xad\xa3\xe5\x9c\xa8\xe4\xbd\xbf\xe7\x94\xa8Q+ Web\xef\xbc\x9ahttp://web.qq.com/\xe3\x80\x91\\",[\\"font\\",{\\"name\\":\\"\xe5\xae\x8b\xe4\xbd\x93\\",\\"size\\":\\"10\\",\\"style\\":[0,0,0],\\"color\\":\\"000000\\"}]]","msg_id":34720001,"clientid":"58472589","psessionid":"..."}&clientid=58472589&psessionid=...'

            """
            try:
                response = self.opener.open(api_url,post_data,self.timeout)
                print 'REALURL',
                print response.geturl()
                print response.info()
                content  = response.read()

                #不出意外，这是返回结果：{"retcode":0,"result":"ok"}
                return content
            except urllib2.HTTPError,e:
                print 'Send MSG Failed.',e
                return ''


        else:
            print 'YOU NEED LOGIN QQ API...'
            return ''
    #def run(self):
    #    self.msgloop();
    def Start(self):
        self.msg_handler = MsgHandler(self.msg_queue)
        # 共启动两个进程, 分别完成消息获取和消息处理的功能
        self.msg_handler.start() # 启动消息处理进程, 对poller 获取的消息进行处理
        self.start()
    def run(self):

        # 创建进程
        #self.msg_handler = MsgHandler(self.msg_queue)
        # 共启动两个进程, 分别完成消息获取和消息处理的功能
        #self.msg_handler.start() # 启动消息处理进程, 对poller 获取的消息进行处理

        self.flag==1

        self.last_poll_time     = time.time()
        self.last_poll_retcode  = 0

        while self.flag==1:

            if self.last_poll_retcode in [102,109]: #如果上次poll的结果是没有消息, retcode = 102, 109
                self.sleep_time += 0.5 # 那么休眠时间增加 500 毫秒(0.5秒)
            elif self.last_poll_retcode in [103,121,108,114,100101]: # 你已经掉线了
                print u'你已经掉线了!!!'
                #login_again = raw_input("Your are offline, Do You Need Login Again?\nPlease input yes or no:")
                #if login_again.strip().lower() == 'yes':
                    #self.login()
                #else:
                #    print 'You do not input `yes`, will quit...'
                #    self.flag = 0 #直接设置标志位, 这样其他的线程可以停了.
                #    break         # 直接跳出while循环, 不去理会get_newflag
            elif self.last_poll_retcode ==0: # 正常的, 继续
                self.sleep_time -= 0.5 # 说明消息多, 就减少休眠时间, 不断的取消息
            else:
                pass

            if self.sleep_time < 0:
                self.sleep_time = 0.5

            print u'%s秒后将开始重新获取消息' % self.sleep_time
            #time.sleep(0.5)

            # 下面将消息以 json obj的形式, 实际上是dict, 放入到消息队列中
            msg_list = self.poll3()# 获取消息
            if msg_list == '' or msg_list is None or len(msg_list)==0:
                pass
            else:
                for msg in msg_list:
                    self.msg_queue.put(msg)


            #self.flag = self.get_newflag()



        self.msg_handler.join()  # 等待消息处理进程结束





