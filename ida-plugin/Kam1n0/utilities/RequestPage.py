from cefpython3 import cefpython as cef
import re, os, platform
import sys
import json
from threading import Thread
from subprocess import Popen, PIPE


def get_python_path():
    return os.path.split(os.path.abspath(os.path.dirname(os.__file__)))[
               0] + "/python"


def get_application_path(target=None):
    if not hasattr(get_application_path, "dir"):
        if hasattr(sys, "frozen"):
            exe_dir = os.path.dirname(sys.executable)
        elif "__file__" in globals():
            exe_dir = os.path.dirname(os.path.realpath(__file__))
        else:
            exe_dir = os.getcwd()
        get_application_path.dir = exe_dir
    # If file is None return current directory without trailing slash.
    if target is None:
        target = ""
    # Only when relative path.
    if not target.startswith("/") and not target.startswith("\\") and (
            not re.search(r"^[\w-]+:", target)):
        path = get_application_path.dir + os.sep + target
        if platform.system() == "Windows":
            path = re.sub(r"[/\\]+", re.escape(os.sep), path)
        path = re.sub(r"[/\\]+$", "", path)
        return path
    return str(target)


class BrowserController:
    def __init__(self, browser):
        self.browser = browser

    def search(self, text):
        self.browser.Find(123, text, True, False, False)

    def stop_search(self):
        self.browser.StopFinding(True)


def send_msg(msg):
    print(msg)
    sys.stdout.flush()


def set_global_handler():
    def on_after_create(browser, **_):
        cef.WindowUtils.SetTitle(browser, 'Kam1n0')
        bindings = cef.JavascriptBindings(
            bindToFrames=True, bindToPopups=False)
        bindings.SetObject("browser_controller", BrowserController(browser))
        bindings.SetFunction("send_msg", send_msg)
        browser.SetJavascriptBindings(bindings)

    cef.SetGlobalClientCallback("OnAfterCreated", on_after_create)


def set_client_handlers(browser, request_url, session):
    client_handlers = [ClientHandler(request_url, session)]
    for handler in client_handlers:
        browser.SetClientHandler(handler)


def set_javascript_bindings(browser, request_url, request_method,
                            request_param, external_data):
    request_param = '{}' if request_param is None else request_param
    external_data = '{}' if external_data is None else external_data
    bindings = cef.JavascriptBindings(
        bindToFrames=True, bindToPopups=False)
    bindings.SetProperty("url", str(request_url))
    bindings.SetProperty("method", str(request_method))
    bindings.SetProperty("param", request_param)
    bindings.SetProperty("external", external_data)
    bindings.SetFunction("send_msg", send_msg)
    bindings.SetObject("browser_controller", BrowserController(browser))
    browser.SetJavascriptBindings(bindings)


class CookieVisitor:
    def Visit(self, cookie, count, total, delete_cookie_out):
        if count == 0:
            print("\n[wxpython.py] CookieVisitor.Visit(): total cookies: %s" \
                  % total)
        print("\n[wxpython.py] CookieVisitor.Visit(): cookie:")
        print("    " + str(cookie.Get()))
        # True to continue visiting cookies
        return True


class ClientHandler(object):
    def __init__(self, request_url, session):
        self.url = request_url
        self.session = session

    def GetCookieManager(self, **_):
        # set cookie in global manager.
        # return None -> all browsers share the same global manager.
        global_manager = cef.CookieManager().GetGlobalManager()
        # global_manager.VisitAllCookies(CookieVisitor())
        if self.session is not None and len(self.session.strip()) > 0:
            cookie = cef.Cookie()
            cookie.SetDomain('')
            cookie.SetName('JSESSIONID')
            cookie.SetValue(self.session)
            cookie.SetPath('/')
            global_manager = cef.CookieManager().GetGlobalManager()
            global_manager.SetCookie(self.url, cookie)

        return None


def create_form(request_url, request_method='get', request_param=None,
                external_data=None, session=None):
    sys.excepthook = cef.ExceptHook
    settings = {
        "product_version": "utilities/2.0.0",
        "user_agent": "utilities/2.0.0",
        'unique_request_context_per_browser': True,
        'persist_session_cookies': False,
        'cache_path': os.path.expanduser("~") + "/Kam1n0/client-web-cache/"
    }
    browser_settings = {
        # enable cross-site scripting. since our request sent from local
        # but the cookie is from remote (different origin)
        "web_security_disabled": True
    }
    cef.Initialize(settings=settings)
    set_global_handler()
    browser = cef.CreateBrowserSync(
        settings=browser_settings,
        url="file://" + get_application_path("resources/operations.html"),
        window_title="Kam1n0")
    set_client_handlers(browser, request_url, session)
    set_javascript_bindings(browser, request_url, request_method,
                            request_param, external_data)
    cef.MessageLoop()
    cef.Shutdown()
    os._exit(1)


def read_from_std_in():
    val = ""
    for line in sys.stdin:
        val += line
    return json.loads(val)


def parse():
    opts = sys.argv[1:]
    data = read_from_std_in()
    create_form(request_url=opts[0],
                request_method=opts[1],
                request_param=data['param'],
                external_data=data['external'],
                session=opts[2])


def create_form_process(request_url, request_method='get', request_param=None,
                        external_data=None, session=None, queue=None):
    if request_param is None:
        request_param = dict()
    if external_data is None:
        external_data = dict()

    param = {'param': request_param, 'external': external_data}

    cmd = [get_python_path(),
           os.path.join(get_application_path(), 'RequestPage.py'),
           request_url,
           request_method,
           session]
    p = Popen(cmd,
              shell=True,
              stdin=PIPE,
              stdout=PIPE,
              stderr=PIPE,
              bufsize=1
              )
    p.stdin.write(json.dumps(param))
    p.stdin.close()
    for line in iter(p.stdout.readline, b''):
        lr = line.rstrip()
        if len(lr) > 0:
            queue.put(lr)
    p.stdout.close()


def test():
    create_form_process(request_url='http://127.0.0.1:8571/userHome',
                        request_method='get',
                        request_param=None,
                        external_data=None,
                        session='2694D98ED7F4CD02E6332CE1292FA6F5')


if __name__ == '__main__':
    parse()
