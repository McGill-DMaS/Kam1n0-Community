# An example of embedding CEF browser in wxPython on Windows.
# Tested with wxPython 2.8.12.1 and 3.0.2.0.

import os, sys
libcef_dll = os.path.join(os.path.dirname(os.path.abspath(__file__)),
        'libcef.dll')
if os.path.exists(libcef_dll):
    # Import a local module
    if (2,7) <= sys.version_info < (2,8):
        import cefpython_py27 as cefpython
    elif (3,4) <= sys.version_info < (3,4):
        import cefpython_py34 as cefpython
    else:
        raise Exception("Unsupported python version: %s" % sys.version)
else:
    # Import an installed package
    from cefpython3 import cefpython

import wx
import time
import re
import uuid
import platform
import inspect
import struct

import urllib2
import urllib
import cookielib
import json

import inspect
scriptPath = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
sys.path.append(os.path.abspath(scriptPath +  '/' + '..'))
import Connector

from xml.dom import minidom

# -----------------------------------------------------------------------------
# Globals

g_applicationSettings = None
g_browserSettings = None
g_commandLineSwitches = None

# Which method to use for message loop processing.
#   EVT_IDLE - wx application has priority
#   EVT_TIMER - cef browser has priority (default)
# It seems that Flash content behaves better when using a timer.
# Not sure if using EVT_IDLE is correct, it doesn't work on Linux,
# on Windows it works fine. See also the post by Robin Dunn:
# https://groups.google.com/d/msg/wxpython-users/hcNdMEx8u48/MD5Jgbm_k1kJ
USE_EVT_IDLE = False # If False then Timer will be used

TEST_EMBEDDING_IN_PANEL = True

# -----------------------------------------------------------------------------

def GetApplicationPath(file=None):
    import re, os, platform
    # On Windows after downloading file and calling Browser.GoForward(),
    # current working directory is set to %UserProfile%.
    # Calling os.path.dirname(os.path.realpath(__file__))
    # returns for eg. "C:\Users\user\Downloads". A solution
    # is to cache path on first call.
    if not hasattr(GetApplicationPath, "dir"):
        if hasattr(sys, "frozen"):
            dir = os.path.dirname(sys.executable)
        elif "__file__" in globals():
            dir = os.path.dirname(os.path.realpath(__file__))
        else:
            dir = os.getcwd()
        GetApplicationPath.dir = dir
    # If file is None return current directory without trailing slash.
    if file is None:
        file = ""
    # Only when relative path.
    if not file.startswith("/") and not file.startswith("\\") and (
            not re.search(r"^[\w-]+:", file)):
        path = GetApplicationPath.dir + os.sep + file
        if platform.system() == "Windows":
            path = re.sub(r"[/\\]+", re.escape(os.sep), path)
        path = re.sub(r"[/\\]+$", "", path)
        return path
    return str(file)

def GetLogPath(file=None):
    if file is None:
        return os.path.expanduser("~") + "/Kam1n0/"
    else:
        return os.path.expanduser("~") + "/Kam1n0/" + file

def ExceptHook(excType, excValue, traceObject):
    import traceback, os, time, codecs
    # This hook does the following: in case of exception write it to
    # the "error.log" file, display it to the console, shutdown CEF
    # and exit application immediately by ignoring "finally" (os._exit()).
    errorMsg = "\n".join(traceback.format_exception(excType, excValue,
            traceObject))
    errorFile = GetLogPath("error.log")
    try:
        appEncoding = cefpython.g_applicationSettings["string_encoding"]
    except:
        appEncoding = "utf-8"
    if type(errorMsg) == bytes:
        errorMsg = errorMsg.decode(encoding=appEncoding, errors="replace")
    try:
        with codecs.open(errorFile, mode="a", encoding=appEncoding) as fp:
            fp.write("\n[%s] %s\n" % (
                    time.strftime("%Y-%m-%d %H:%M:%S"), errorMsg))
    except:
        print("[wxpython.py] WARNING: failed writing to error file: %s" % (
                errorFile))
    # Convert error message to ascii before printing, otherwise
    # you may get error like this:
    # | UnicodeEncodeError: 'charmap' codec can't encode characters
    errorMsg = errorMsg.encode("ascii", errors="replace")
    errorMsg = errorMsg.decode("ascii", errors="replace")
    print("\n"+errorMsg+"\n")
    cefpython.QuitMessageLoop()
    cefpython.Shutdown()
    os._exit(1)

class MainFrame(wx.Frame):
    browser = None
    mainPanel = None

    def GetHandleForBrowser(self):
        if self.mainPanel:
            return self.mainPanel.GetHandle()
        else:
            return self.GetHandle()

    def __init__(self, url=None, popup=False, params = None):
        if popup:
            title = os.path.basename(url)
        else:
            title = "Kam1n0"
        wx.Frame.__init__(self, parent=None, id=wx.ID_ANY,
                title=title)
        size=(500,500)

        # icon
        #setup icon object
        #icon = wx.Icon(GetApplicationPath("www/img/favicon.ico"), wx.BITMAP_TYPE_ICO)

        #setup taskbar icon
        #tbicon = wx.TaskBarIcon()
        #tbicon.SetIcon(icon, "McGill Icon")
        loc = wx.IconLocation(GetApplicationPath("www/img/favicon.ico"), 0)
        self.SetIcon(wx.IconFromLocation(loc))

        # This is an optional code to enable High DPI support.
        if "auto_zooming" in g_applicationSettings \
                and g_applicationSettings["auto_zooming"] == "system_dpi":
            # This utility function will adjust width/height using
            # OS DPI settings. For 800/600 with Win7 DPI settings
            # being set to "Larger 150%" will return 1200/900.
            size = cefpython.DpiAware.CalculateWindowSize(size[0], size[1])

        self.SetSize(size)

        if not url:
            url = "file://"+GetApplicationPath("www/FragmentInput.html")
            # Test hash in url.
            # url += "#test-hash"


        if TEST_EMBEDDING_IN_PANEL:
            # You also have to set the wx.WANTS_CHARS style for
            # all parent panels/controls, if it's deeply embedded.
            self.mainPanel = wx.Panel(self, style=wx.WANTS_CHARS)

        # Global client callbacks must be set before browser is created.
        self.clientHandler = ClientHandler()
        cefpython.SetGlobalClientCallback("OnCertificateError",
                self.clientHandler._OnCertificateError)
        cefpython.SetGlobalClientCallback("OnBeforePluginLoad",
                self.clientHandler._OnBeforePluginLoad)
        cefpython.SetGlobalClientCallback("OnAfterCreated",
                self.clientHandler._OnAfterCreated)

        windowInfo = cefpython.WindowInfo()
        windowInfo.SetAsChild(self.GetHandleForBrowser())
        self.browser = cefpython.CreateBrowserSync(windowInfo,
                browserSettings=g_browserSettings,
                navigateUrl=url)

        self.clientHandler.mainBrowser = self.browser
        self.browser.SetClientHandler(self.clientHandler)

        jsBindings = cefpython.JavascriptBindings(
            bindToFrames=False, bindToPopups=True)
        jsBindings.SetProperty("pyProperty", "This was set in Python")
        jsBindings.SetProperty("pyConfig", ["This was set in Python",
                {"name": "Nested dictionary", "isNested": True},
                [1,"2", None]])

        global gdata
        if gdata is None:
            gdata = GetData()

        self.javascriptExternal = JavascriptExternal(self.browser, gdata)
        self.javascriptExternal.frame = self
        jsBindings.SetObject("external", self.javascriptExternal)
        jsBindings.SetProperty("GData", gdata)
        if not params is None:
            jsBindings.SetProperty("params", params)
        self.browser.SetJavascriptBindings(jsBindings)

        if self.mainPanel:
            self.mainPanel.Bind(wx.EVT_SET_FOCUS, self.OnSetFocus)
            self.mainPanel.Bind(wx.EVT_SIZE, self.OnSize)
        else:
            self.Bind(wx.EVT_SET_FOCUS, self.OnSetFocus)
            self.Bind(wx.EVT_SIZE, self.OnSize)

        self.Bind(wx.EVT_CLOSE, self.OnClose)
        if USE_EVT_IDLE and not popup:
            # Bind EVT_IDLE only for the main application frame.
            self.Bind(wx.EVT_IDLE, self.OnIdle)

    def CreateMenu(self):
        filemenu = wx.Menu()
        filemenu.Append(1, "Open")
        exit = filemenu.Append(2, "Exit")
        self.Bind(wx.EVT_MENU, self.OnClose, exit)
        aboutmenu = wx.Menu()
        aboutmenu.Append(1, "CEF Python")
        menubar = wx.MenuBar()
        menubar.Append(filemenu,"&File")
        menubar.Append(aboutmenu, "&About")
        self.SetMenuBar(menubar)

    def CreateSearchBar(self):
        toolbar = wx.ToolBar(self, -1, style=wx.TB_HORIZONTAL | wx.NO_BORDER)
        toolbar.AddSimpleTool(1, wx.TextCtrl(self, style=wx.TE_NO_VSCROLL))
        toolbar.Realize()



    def OnFind(self, event):
        self.browser.Find(12, "a", True, False, True)

    def OnSetFocus(self, event):
        cefpython.WindowUtils.OnSetFocus(self.GetHandleForBrowser(), 0, 0, 0)

    def OnSize(self, event):
        cefpython.WindowUtils.OnSize(self.GetHandleForBrowser(), 0, 0, 0)

    def OnClose(self, event):
        # Remove all CEF browser references so that browser is closed
        # cleanly. Otherwise there may be issues for example with cookies
        # not being flushed to disk when closing app immediately
        # (Issue 158).

        #td = self.javascriptExternal.mainBrowser.GetMainFrame().GetProperty("pyProperty")
        #print td

        del self.javascriptExternal.mainBrowser
        del self.clientHandler.mainBrowser
        del self.browser

        # Destroy wx frame, this will complete the destruction of CEF browser
        self.Destroy()

        # In wx.chromectrl calling browser.CloseBrowser and/or self.Destroy
        # may cause crashes when embedding multiple browsers in tab
        # (Issue 107). In such case instead of calling CloseBrowser/Destroy
        # try this code:
        # | self.browser.ParentWindowWillClose()
        # | event.Skip()

    def OnIdle(self, event):
        cefpython.MessageLoopWork()

class JavascriptExternal:
    mainBrowser = None

    def __init__(self, mainBrowser, gdata):
        self.mainBrowser = mainBrowser
        self.gdata = gdata

    def Search(self, text):
        self.mainBrowser.Find(123, text, True, False, False)

    def GoBack(self):
        self.mainBrowser.GoBack()

    def GoForward(self):
        self.mainBrowser.GoForward()

    def CreateAnotherBrowser(self, url=None):
        frame = MainFrame(url=url)
        frame.Show()

    def Print(self, message):
        print(message)


    def ExecuteFunction(self, *args):
        self.mainBrowser.GetMainFrame().ExecuteFunction(*args)

    def CreatePopup(self, file, params, max=0):
        #self.mainBrowser.GetMainFrame().ExecuteJavascript(
        #        "window.alert(\"%s\")" % url)
        url = "file://"+GetApplicationPath("www/"+file)
        frame = MainFrame(url=url, popup=True, params=params)
        frame.Show()
        if max == 1:
            frame.Maximize(True)

    def GetFunc(self, fid, callBack):
        global connector
        if connector is None:
            connector = GetConnector()
        content = connector.getFunc(fid)
        callBack.Call(content[1])

    def GetComments(self, fid, callBack):
        global connector
        if connector is None:
            connector = GetConnector()
        content = connector.getComments(fid)
        callBack.Call(content[1])

    def PostComment(self, fid, offset, date, comment, callBack, op=None):
        global connector
        if connector is None:
            connector = GetConnector()
        content = connector.postComment(fid, offset, date, comment, op)
        callBack.Call(content[1])

    def IndexFunc(self, fid, callBack):
        global connector, funcSurrogateMap
        if connector is None:
            connector = GetConnector()
        if funcSurrogateMap is None:
            funcSurrogateMap = GetFuncSurrogateMap()
        funcSurrogate = funcSurrogateMap[long(fid)]
        if funcSurrogate is None:
            callBack.Call("Failed to persist this function.")
        else:
            content = connector.indexFunc(funcSurrogate)
            if content[0] == Connector.OK:
                callBack.Call("You have indexed current function.")
            callBack.Call(content[1])

    def SetInputText(self, txt):
        global inputText
        inputText = txt

        print "###########"
        global inputText
        print inputText
        print "###########"

        del self.frame.javascriptExternal.mainBrowser
        del self.frame.clientHandler.mainBrowser
        del self.frame.browser

        # Destroy wx frame, this will complete the destruction of CEF browser
        self.frame.Destroy()

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


class ClientHandler:
    mainBrowser = None # May be None for global client callbacks.

    def __init__(self):
        pass


    def GetAuthCredentials(self, browser, frame, isProxy, host, port, realm,
            scheme, callback):
        callback.Continue(username="test", password="test")
        return True

    def OnQuotaRequest(self, browser, originUrl, newSize, callback):
        callback.Continue(True)
        return True


    def OnProtocolExecution(self, browser, url, allowExecutionOut):
        # There's no default implementation for OnProtocolExecution on Linux,
        # you have to make OS system call on your own. You probably also need
        # to use LoadHandler::OnLoadError() when implementing this on Linux.

        if url.startswith("magnet:"):
            allowExecutionOut[0] = True

    def _OnBeforePluginLoad(self, browser, url, policyUrl, info):
        # This is a global callback set using SetGlobalClientCallback().
        # Plugins are loaded on demand, only when website requires it,
        # the same plugin may be called multiple times.
        # This callback is called on the IO thread, thus print messages
        # may not be visible.
        # False to allow, True to block plugin.
        return False

    def _OnCertificateError(self, certError, requestUrl, callback):
        # This is a global callback set using SetGlobalClientCallback().

        if requestUrl == "https://testssl-expire.disig.sk/index.en.html":
            return False
        if requestUrl \
                == "https://testssl-expire.disig.sk/index.en.html?allow=1":
            callback.Continue(True)
            return True
        return False


    def _Browser_LoadUrl(self, browser):
        if browser.GetUrl() == "data:text/html,Test#Browser.LoadUrl":
             browser.LoadUrl("file://"+GetApplicationPath("www/CloneGraph.html"))

    # -------------------------------------------------------------------------
    # LifespanHandler
    # -------------------------------------------------------------------------


    def _CreatePopup(self, url):
        frame = MainFrame(url=url, popup=True)
        frame.Show()

    def _OnAfterCreated(self, browser):
        return;



class MyApp(wx.App):
    timer = None
    timerID = 1
    mainFrame = None

    def OnInit(self):
        if not USE_EVT_IDLE:
            self.CreateTimer()
        self.mainFrame = MainFrame()
        self.SetTopWindow(self.mainFrame)
        self.mainFrame.Show()

        return True

    def CreateTimer(self):
        # See "Making a render loop":
        # http://wiki.wxwidgets.org/Making_a_render_loop
        # Another approach is to use EVT_IDLE in MainFrame,
        # see which one fits you better.
        self.timer = wx.Timer(self, self.timerID)
        self.timer.Start(10) # 10ms
        wx.EVT_TIMER(self, self.timerID, self.OnTimer)

    def OnTimer(self, event):
        cefpython.MessageLoopWork()

    def OnExit(self):
        if not USE_EVT_IDLE:
            self.timer.Stop()


def GetData():
        str = ""
        for line in sys.stdin:
            str += line
        return str

def GetFuncSurrogateMap():
    global funcSurrogateMap, gdata
    if funcSurrogateMap is None:
        pgd = json.loads(gdata)
        funcSurrogateMap = {}
        for res in pgd['results']:
            func = res['function']
            funcSurrogateMap[func['functionId']] = func['surrogate']
            func['surrogate'] = None
    return funcSurrogateMap

def GetConnector():
    global gdata
    if gdata is None:
        gdata = GetData()
    pgd = json.loads(gdata)
    protocol = pgd['cnn']['protocol']
    server = pgd['cnn']['server']
    port = pgd['cnn']['port']
    ssid = pgd['cnn']['ssid']
    global connector
    connector = Connector.Connector(
        server=server,
        protocol=protocol,
        port=port,
        ssid=ssid)
    return connector

if __name__ == '__main__':

    global gdata, funcSurrogateMap, inputText
    gdata = None
    funcSurrogateMap = None
    inputText = ['']

    global connector
    connector = None

    # Intercept python exceptions. Exit app immediately when exception
    # happens on any of the threads.
    # sys.excepthook = ExceptHook

    # Application settings
    g_applicationSettings = {
        # Disk cache
        # "cache_path": "webcache/",

        # CEF Python debug messages in console and in log_file
        "debug": False,
        # Set it to LOGSEVERITY_VERBOSE for more details
        "log_severity": cefpython.LOGSEVERITY_ERROR,
        # Set to "" to disable logging to a file
        "log_file": GetLogPath("debug.log"),
        # This should be enabled only when debugging
        "release_dcheck_enabled": True,

        # These directories must be set on Linux
        "locales_dir_path": cefpython.GetModuleDirectory()+"/locales",
        "resources_dir_path": cefpython.GetModuleDirectory(),
        # The "subprocess" executable that launches the Renderer
        # and GPU processes among others. You may rename that
        # executable if you like.
        "browser_subprocess_path": "%s/%s" % (
            cefpython.GetModuleDirectory(), "subprocess"),

        # This option is required for the GetCookieManager callback
        # to work. It affects renderer processes, when this option
        # is set to True. It will force a separate renderer process
        # for each browser created using CreateBrowserSync.
        "unique_request_context_per_browser": True,
        # Downloads are handled automatically. A default SaveAs file
        # dialog provided by OS will be displayed.

        "downloads_enabled": True,
        # Remote debugging port, required for Developer Tools support.
        # A value of 0 will generate a random port. To disable devtools
        # support set it to -1.
        "remote_debugging_port": 0,
        # Mouse context menu
        "context_menu": {
            "enabled": True,
            "navigation": True, # Back, Forward, Reload
            "print": True,
            "view_source": False,
            "external_browser": False, # Open in external browser
            "devtools": True, # Developer Tools
        },

        # See also OnCertificateError which allows you to ignore
        # certificate errors for specific websites.
        "ignore_certificate_errors": True,
    }

    # You can comment out the code below if you do not want High
    # DPI support. If you disable it text will look fuzzy on
    # high DPI displays.
    #
    # Enabling High DPI support in app can be done by
    # embedding a DPI awareness xml manifest in executable
    # (see Issue 112 comment #2), or by calling SetProcessDpiAware
    # function. Embedding xml manifest is the most reliable method.
    # The downside of calling SetProcessDpiAware is that scrollbar
    # in CEF browser is smaller than it should be. This is because
    # DPI awareness was set too late, after the CEF dll was loaded.
    # To fix that embed DPI awareness xml manifest in the .exe file.
    #
    # There is one bug when enabling High DPI support - fonts in
    # javascript dialogs (alert) are tiny. However, you can implement
    # custom javascript dialogs using JavascriptDialogHandler.
    #
    # Additionally you have to set "auto_zomming" application
    # setting. High DPI support is available only on Windows.
    # You may set auto_zooming to "system_dpi" and browser
    # contents will be zoomed using OS DPI settings. On Win7
    # these can be set in: Control Panel > Appearance and
    # Personalization > Display.
    #
    # Example values for auto_zooming are:
    #   "system_dpi", "0.0" (96 DPI), "1.0" (120 DPI),
    #   "2.0" (144 DPI), "-1.0" (72 DPI)
    # Numeric value means a zoom level.
    # Example values that can be set in Win7 DPI settings:
    #   Smaller 100% (Default) = 96 DPI = 0.0 zoom level
    #   Medium 125% = 120 DPI = 1.0 zoom level
    #   Larger 150% = 144 DPI = 2.0 zoom level
    #   Custom 75% = 72 DPI = -1.0 zoom level
    g_applicationSettings["auto_zooming"] = "system_dpi"
    cefpython.DpiAware.SetProcessDpiAware()

    # Browser settings. You may have different settings for each
    # browser, see the call to CreateBrowserSync.
    g_browserSettings = {
        # "plugins_disabled": True,
        # "file_access_from_file_urls_allowed": True,
        # "universal_access_from_file_urls_allowed": True,
    }

    # Command line switches set programmatically
    g_commandLineSwitches = {
        # "proxy-server": "socks5://127.0.0.1:8888",
        # "no-proxy-server": "",
        # "enable-media-stream": "",
        # "disable-gpu": "",

    }

    cefpython.Initialize(g_applicationSettings, g_commandLineSwitches)

    app = MyApp(False)
    app.MainLoop()

    # Let wx.App destructor do the cleanup before calling
    # cefpython.Shutdown(). This is to ensure reliable CEF shutdown.
    del app

    cefpython.Shutdown()

