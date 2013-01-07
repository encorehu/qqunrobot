# -*- coding: utf-8 -*-
import threading
import time
import random
#Consumer thread 消费者
class MsgHandler(threading.Thread):

    def __init__(self,queue):
        threading.Thread.__init__(self)
        self.queue=queue
        #self.flag_func = flag_func

    def run(self):
        while True:
            msg = self.queue.get()
            try:
                poll_type = msg['poll_type']
                poll_type = poll_type.lower()
            except KeyError:
                continue
            if(poll_type == 'robotquit'):
                self.queue.task_done()
                break;
            elif poll_type == 'message':
                self.handle_message(msg)
            elif poll_type == 'group_message':
                self.handle_group_message(msg)
            elif poll_type == 'sys_g_msg':
                self.handle_sys_g_msg(msg)
            elif poll_type == 'sess_message':
                self.handle_sess_message(msg)
            elif poll_type == 'group_web_message':
                self.handle_group_web_message(msg)
            elif poll_type == 'input_notify':
                self.handle_input_notify(msg)
            elif poll_type == 'buddies_status_change':
                self.handle_buddies_status_change(msg)
            else:
                self.handle_unknown(msg)
                #time.sleep(random.randrange(5))
            self.queue.task_done()

            #self.flag = self.flag_func() # 重新获取机器人运行标志, 看看是否还允许它运行.


            #print "%s: %s finished!" %(time.ctime(), self.getName())

    def handle_message(self, msg):
        """
        {
            "poll_type":"message",
            "value":{
                "msg_id":10718,
                "from_uin":959769627,
                "to_uin":2484810628,
                "msg_id2":768274,
                "msg_type":9,
                "reply_ip":176752043,
                "time":1357309746,
                "content":[
                    ["font",{"size":11,"color":"004080","style":[0,0,0],"name":"\u5FAE\u8F6F\u96C5\u9ED1"}],
                    "\u65B9\u5F0F "
                ]
            }
        },
        {
            "poll_type":"input_notify",
            "value":{
                "msg_id":38188,
                "from_uin":959769627,
                "to_uin":2484810628,
                "msg_id2":3908646048,
                "msg_type":121,
                "reply_ip":4294967295
            }
        }
        """
        print u'有好友消息'

        #        print 'msg_id',    msg['value']['msg_id']
        #        print 'from_uin',  msg['value']['from_uin']
        #        print 'to_uin',    msg['value']['to_uin']
        #        print 'msg_id2',   msg['value']['msg_id2']
        #        print 'msg_type',  msg['value']['msg_type']
        #        print 'reply_ip',  msg['value']['reply_ip']
        #        print 'group_code',msg['value']['group_code']
        #        print 'send_uin',  msg['value']['send_uin']
        #        print 'seq',       msg['value']['seq']
        #        print 'time',      msg['value']['time']
        #        print 'info_seq',  msg['value']['info_seq']
        content =''
        for piece in msg['value']['content']:
            if type(piece) in [list,tuple,set,dict]:
                continue # 这个里面一般是图片, 以后再处理
            else:
                content +=piece
        print content
        #print 'content',   msg['value']['content'][0]
        #print 'content',   msg['value']['content'][1]
        print u'%s %s\n%s' % (msg['value']['from_uin'], msg['value']['time'],content)
        pass

    def handle_group_message(self, msg):
        """
        {
            "poll_type":"group_message",
            "value":{
                "msg_id":6212,
                "from_uin":404382505,
                "to_uin":2484810628,
                "msg_id2":163835,
                "msg_type":43,
                "reply_ip":176882280,
                "group_code":3463861631,
                "send_uin":4025723434,
                "seq":41797,
                "time":1357306484,
                "info_seq":21360652,
                "content":[
                    ["font",{"size":12,"color":"8000ff","style":[1,0,0],"name":"\u5B8B\u4F53"}],
                    "\u522B\u8D70\u554A"
                    ]
                }
        }
        """
        print u'群(%s)有群消息'  % msg['value']['info_seq']
        content =''
        for piece in msg['value']['content']:
            if type(piece) in [list,tuple,set,dict]:
                continue
            else:
                content +=piece
        print content
        #print 'content',   msg['value']['content'][0]
        #print 'content',   msg['value']['content'][1]
        print u'%s %s\n%s' % (msg['value']['send_uin'], msg['value']['time'],content)
        pass

    def handle_sys_g_msg(self, msg):
        """
        {
    		"poll_type":"sys_g_msg",
    		"value":{
    			"msg_id":39570,
    			"from_uin":1489552172,
    			"to_uin":2484810628,
    			"msg_id2":397480,
    			"msg_type":34,
    			"reply_ip":176752049,
    			"type":"group_leave",
    			"gcode":3461815188,
    			"t_gcode":21360652,
    			"op_type":3,
    			"old_member":2525168823,
    			"t_old_member":"",
    			"admin_uin":3504017314,
    			"t_admin_uin":"",
    			"admin_nick":"\u7BA1\u7406\u5458"
    		}
    	},
    	"""

        print u'有群系统消息'
        sys_g_msg_type = msg['value']['type']
        if sys_g_msg_type == 'group_leave':
            print u'%s 离开了群(%s)' % (msg['value']['from_uin'], msg['value']['t_gcode'])
        elif sys_g_msg_type == 'group_request_join':
            print u'%s 请求加入群(%s)\n理由:%s' % (msg['value']['request_uin'], msg['value']['t_gcode'], msg['value']['msg'])
        else:
            print u'神马情况, 没遇到过%s' % sys_g_msg_type
        pass

    def handle_sess_message(self, msg):
        print u'sess_message'
        pass

    def handle_group_web_message(self, msg):
        print u'有群动态'
        pass

    def handle_input_notify(self, msg):
        print u'对方正在输入...'
        pass

    def handle_buddies_status_change(self,msg):
        print u'有人上下线了'
        pass

    def handle_unknown(self, msg):
        print u'有未知或者临时消息'
        pass
