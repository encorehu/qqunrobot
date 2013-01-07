qqunrobot
=========

a QQ Group(qun)  Service Robot, use python2.7 now
一个QQ群服务的机器人, 使用Python2.7编写

==基础

 - 基于webqq协议
 - 基于python2.7

==依赖 Requirements
 - gevent

==已经实现的功能
 - 登录webqq
 - 接受群消息, 群系统消息, 好友消息, 临时消息

==存在问题
 - 发送消息, 好友或者群能不能收到看运气
 - 命令模式的功能还没开发

==下一步打算
 - 自然语言处理, 自动聊天
 - 网络服务整合, 包括天气预报, 看看笑话, 电影,音乐排行榜等等
 - 牛人博客精选
 - 网站问答系统连接

==开发约定
 1. class 类名以驼峰式命名
 2. 函数和参数都以小写字母和下划线连接
 3. 所有插件的命令以@这个特殊符号打头, 比如@天气 北京 用来查北京近3天的天气预报
 4. 所有的注释或者文档使用 markdown 编写, 标点符号统一使用英文标点, 不用中文标点. 英文标点后必须加一个英文空格. 汉字句子中的所有的英文单词左边和右边均保留一个英文空格. 
