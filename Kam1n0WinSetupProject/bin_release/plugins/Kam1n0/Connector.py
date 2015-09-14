import urllib2
import urllib
import cookielib
import json
import os
import sys
from subprocess import  Popen, PIPE
import threading
import subprocess

ERROR_CONNECTION = 2
ERROR_LOGIN = 1
ERROR_HTTP = 3
OK = 0

class Connector:

    URL_PROTOCOL = "http://"
    URL_PORT = "9988"
    URL_LOCAL   = "127.0.0.1"
    URL_REMOTE  = "132.206.199.121"
    URL_LOGIN   = "/j_security_check"
    URL_SEARCH  = "/FunctionClone"
    URL_SEARCH2 = "/FunctionSurrogateClone"
    URL_GETFUNC = "/FunctionFlow"
    URL_GETCOMM = "/Comment"
    URL_INDFUNC = "/admin/BinarySurrogateIndex"
    URL_ADMIN = "/admin/IdaProDashboard.html"

    def __init__(self, server = URL_LOCAL, protocol = URL_PROTOCOL, port = URL_PORT, un="admin", pw="admin", ssid = None):
        self.server = server
        self.cj = None
        self.protocol = protocol
        self.port = port
        self.ssid = ssid
        self.headers ={"User-agent":"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1",
                  "dataType":"json"}
        self.un = un
        self.pw = pw

    def reset(self):
        self.cj = None

    def toMap(self):
        return {'server':self.server,
                'protocol':self.protocol,
                'port':self.port,
                'un':self.un,
                'pw':self.pw,
                'key':self.un + " @ " + self.protocol + self.server + ":" + self.port}

    def getConnectionURL(self):
        return self.protocol + self.server + ":" + self.port

    def getSessionID(self):
        if self.cj is None:
            return 0
        else:
            return self.cj._cookies[self.server]['/']['JSESSIONID'].value

    def login(self):

        try:
            url = self.getConnectionURL() + self.URL_LOGIN
            data={"j_username":self.un,"j_password":self.pw}
            post_data=urllib.urlencode(data)

            cj = cookielib.MozillaCookieJar()
            opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
            headers = {"User-agent":"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1"}
            urllib2.install_opener(opener)

            req = urllib2.Request(url,post_data,headers)
            response = opener.open(req)
            content = response.read()

            self.cj = cj

        except urllib2.HTTPError, e:
            return ERROR_HTTP, "Error: " + str(e.code)
        except urllib2.URLError, e:
            return ERROR_CONNECTION, e.reason
        except Exception as e:
            return ERROR_CONNECTION, e.message

        if "window.location.replace" in content:
            return OK, "O:"
        else:
            return ERROR_LOGIN, "E:login error"

    def make_cookie(self, name, value, domain):
        return cookielib.Cookie(
        version=0,
        name=name,
        value=value,
        port=None,
        port_specified=False,
        domain=domain,
        domain_specified=False,
        domain_initial_dot=False,
        path="/",
        path_specified=True,
        secure=False,
        expires=None,
        comment=None,
        comment_url=None,
        discard=True,
        rest={},
        rfc2109=False
        )

    def validateCJ(self):
        if self.cj is None:
            if not self.ssid is None:
                self.cj = cookielib.CookieJar()
                opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(self.cj))
                urllib2.install_opener(opener)
                self.cj.set_cookie(self.make_cookie('JSESSIONID', self.ssid, self.server))
                return self.cj
            else:
                return 0
        else:
            return self.cj

    def query(self, asmf, fname):

        if self.validateCJ() == 0:
            return (ERROR_LOGIN, "E:")

        url = self.getConnectionURL() + self.URL_SEARCH
        data={"asmf": asmf,
              "fname": fname}
        return self.doPost(url, data)

    def querySurrogate(self, surrogate):
        if self.validateCJ() == 0:
           return (ERROR_LOGIN, "E:")

        url = self.getConnectionURL() + self.URL_SEARCH2
        data={"func": json.dumps(surrogate) }
        return self.doPost(url, data)


    def getFunc(self, fid):
        if self.validateCJ() is None:
            return (ERROR_LOGIN, "E:")

        url = self.getConnectionURL() + self.URL_GETFUNC
        data={"fid" : fid}
        return self.doGet(url, data)

    def mergeFuncs(self, dps):

        # merge data
        dp = {}
        dp['cnn'] = dps[-1]['cnn']
        results = []
        for odp in dps:
            results += odp['results']
        dp['results'] = results
        dp['cloneGraph'] = {}
        links = []
        nodes = []
        dp['cloneGraph']['links'] = links
        dp['cloneGraph']['nodes'] = nodes


        # translate binary id
        bidMap = {}
        for res in dp['results']:
            bidMap[res['function']['binaryId']] = -1
            for clone in res['clones']:
                bidMap[clone['binaryId']] = -1

        bid = 0
        for id in bidMap:
            bidMap[id] = bid
            bid += 1


        # translate function id
        fidMap = {}
        fid = 0
        for res in dp['results']:
            func = res['function']
            if func['functionId'] not in fidMap:
                fidMap[func['functionId']] = fid
                fid += 1
                node = {}
                node['binaryGroupID'] = bidMap[func['binaryId']]
                node['binaryGroupName'] = func['binaryName']
                node['clones'] = []
                node['name'] = func['functionName']
                nodes.append(node)

        for res in dp['results']:
            for clone in res['clones']:
                if clone['functionId'] not in fidMap:
                    fidMap[clone['functionId']] = fid
                    fid += 1
                    snode = {}
                    snode['binaryGroupID'] = bidMap[clone['binaryId']]
                    snode['binaryGroupName'] = clone['binaryName']
                    snode['clones'] = []
                    snode['name'] = clone['functionName']
                    nodes.append(snode)

        # generate link
        for res in dp['results']:
            func = res['function']
            for clone in res['clones']:
                link = {}
                link['source'] = fidMap[func['functionId']]
                link['target'] = fidMap[clone['functionId']]
                link['value'] = clone['similarity']

                node = nodes[link['source']]
                node['clones'].append([link['target'], link['value']])

                node = nodes[link['target']]
                node['clones'].append([link['source'], link['value']])

                links.append(link)

        return dp

    def indexFunc(self, surrogate):
        if self.validateCJ() is None:
            return (ERROR_LOGIN, "E:")

        url = self.getConnectionURL() + self.URL_INDFUNC
        data={"func" : json.dumps(surrogate) }
        return self.doPost(url,data)

    def getComments(self, fid):
        if self.validateCJ() is None:
            return ERROR_LOGIN

        url = self.getConnectionURL() + self.URL_GETCOMM
        data={"fid" : fid}
        return self.doGet(url,data)

    def postComment(self, fid, offset, date, comment, op):
        if self.validateCJ() == 0:
            return (ERROR_LOGIN, "E:")

        url = self.getConnectionURL() + self.URL_GETCOMM
        data={"fid": fid,
              "offset": offset,
              "date": date,
              "comment": comment}
        if not op is None:
            data['op'] = op
        return self.doPost(url, data)

    def doGet(self, url, data):
        try:
            getStr = url + "?" + urllib.urlencode(data)
            response = urllib2.urlopen(url=getStr)
            content = response.read()
        except urllib2.HTTPError, e:
            return 3, "Error: "+ str(e.code)
        except urllib2.URLError, e:
            return 2, e.reason
        except Exception as e:
            return ERROR_CONNECTION, e.message

        if "<!DOCTYPE html>" in content:
            return 1, content
        else:
            return 0,content

    def doPost(self, url, data):

        try:
            post_data=urllib.urlencode(data)
            response = urllib2.urlopen(url=url, data=post_data)
            content = response.read()

        except urllib2.HTTPError, e:
            return ERROR_HTTP, "Error: " + str(e.code)
        except urllib2.URLError, e:
            return ERROR_CONNECTION, e.reason
        except Exception as e:
            return ERROR_CONNECTION, e.message

        if "<!DOCTYPE html>" in content:
            return ERROR_LOGIN, content
        else:
            return OK,content

    def tryLoginAndExecute(self, queryFunction, params):
        code, content = queryFunction(params)
        if code > OK:
            if code == ERROR_LOGIN:
                code, content = self.login()
                if code == OK:
                    code, content = queryFunction(params)
                    code, content = self.getCodeDescription(code, content)
                else:
                    code, content = self.getCodeDescription(code, content)
        return code, content

    @staticmethod
    def getCodeDescription(code, content):
        if code == OK:
            content = content
        elif code == ERROR_LOGIN:
            content = "Login error. Please check your password/username combination."
        elif code == ERROR_HTTP:
            content = "Http Error. Code [%s]. Please check if other services are running on this port." % content
        elif code == ERROR_CONNECTION:
            content = content
        else:
            content = "Connection failure. %s" % content
        return code, content


    def getPythonExePath(self):
        return os.path.split(os.path.abspath(os.path.dirname(os.__file__)))[0] + "/python"

    def openAdminPage(self):

         cmd = [self.getPythonExePath(),
                os.path.dirname(os.path.realpath(__file__)) + "/Forms/AdminForm.py"]
         p = Popen(cmd,
              shell=True,
              stdin=PIPE,
              stdout=PIPE,
              stderr=PIPE)

         cnn = {}
         cnn['server'] = self.server
         cnn['protocol'] = self.protocol
         cnn['port'] = self.port
         cnn['ssid'] = self.getSessionID()
         cnn['url'] = self.getConnectionURL() + self.URL_ADMIN

         stdout, stderr = p.communicate(json.dumps(cnn))

