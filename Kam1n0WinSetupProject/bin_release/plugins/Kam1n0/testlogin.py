
import urllib2
import urllib
import cookielib
import inspect
import ctypes
import threading
import time

def login():
    url = "http://127.0.0.1:9988/j_security_check"
    data={"j_username":"admin","j_password":"admin"}
    post_data=urllib.urlencode(data)

    cj = cookielib.MozillaCookieJar()
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
    urllib2.install_opener(opener)
    headers ={"User-agent":"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1"}

    req=urllib2.Request(url,post_data,headers)
    response=opener.open(req)
    content = response.read()
    #print content.indexOf('a')
    print content

    return cj

def check(cj):

    print cj

    with open("data.txt", "r") as mFile:
        query = mFile.read()

    sid = cj._cookies['127.0.0.1']['/']['JSESSIONID'].value

    cj2 = cookielib.CookieJar()

    url = "http://127.0.0.1:9988/FunctionClone"
    data={"asmf":query,"fname":"test"}
    post_data=urllib.urlencode(data)

    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj2))
    urllib2.install_opener(opener)
    headers ={"User-agent":"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1",
              "dataType":"json"}
    cj2 = cj2.set_cookie(make_cookie('JSESSIONID', sid, '127.0.0.1'))

    req=urllib2.Request(url,post_data,headers)
    response=opener.open(req)
    print response.read()

def make_cookie(name, value, domain):
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

def GetFunc(protocol, server, port, ssid, fid, callback):
        cj = cookielib.CookieJar()
        url = protocol+server+":"+port + "/FunctionFlow"
        data={"fid" : fid}
        getStr = url + "?" + urllib.urlencode(data)
        print url

        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
        urllib2.install_opener(opener)
        headers ={"User-agent":"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1",
                  "dataType":"json"}
        cj.set_cookie(make_cookie('JSESSIONID', ssid, server))

        req=urllib2.Request(url=getStr,headers=headers)
        response=opener.open(req)
        content = response.read()

        print content

def main():
    cj = login()
    check(cj)
    sid = cj._cookies['127.0.0.1']['/']['JSESSIONID'].value
    GetFunc("http://", "127.0.0.1", "9988", sid, "4100973893041914430", None)


def _async_raise(tid, exctype):
    """raises the exception, performs cleanup if needed"""
    if not inspect.isclass(exctype):
        raise TypeError("Only types can be raised (not instances)")
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, ctypes.py_object(exctype))
    if res == 0:
        raise ValueError("invalid thread id")
    elif res != 1:
        # """if it returns a number greater than one, you're in trouble,
        # and you should call it again with exc=NULL to revert the effect"""
        ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, 0)
        raise SystemError("PyThreadState_SetAsyncExc failed")

class Thread(threading.Thread):
    def _get_my_tid(self):
        """determines this (self's) thread id"""
        if not self.isAlive():
            raise threading.ThreadError("the thread is not active")

        # do we have it cached?
        if hasattr(self, "_thread_id"):
            return self._thread_id

        # no, look for it in the _active dict
        for tid, tobj in threading._active.items():
            if tobj is self:
                self._thread_id = tid
                return tid

        raise AssertionError("could not determine the thread's id")

    def raise_exc(self, exctype):
        """raises the given exception type in the context of this thread"""
        _async_raise(self._get_my_tid(), exctype)

    def terminate(self):
        """raises SystemExit in the context of the given thread, which should
        cause the thread to exit silently (unless caught)"""
        self.raise_exc(SystemExit)

def f():
    try:
        while True:
            time.sleep(10)
            print "outta here"
    except:
        return

t = Thread(target = f)
t.start()
print t.isAlive()
time.sleep(5)
t.terminate()
print t.isAlive()


#main()