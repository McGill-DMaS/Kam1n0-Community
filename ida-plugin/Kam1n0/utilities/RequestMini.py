import urllib2
import urllib
import cookielib
import RequestPage
from threading import Thread
from urlparse import urlparse
from urlparse import urlsplit, urlunsplit

ERROR_CONNECTION = 2
ERROR_LOGIN = 1
ERROR_HTTP = 3
ERROR_CLIENT = 4
OK = 0
MSG = -1


def has_error(error_code, *_):
    return error_code != 0


def get_error_description(error_code, content):
    if error_code == OK:
        content = 'Request Completed.'
    elif error_code == MSG:
        error_code = 'cef-msg'
    elif error_code == ERROR_LOGIN:
        content = "Login error. Please check your " \
                  "password/username combination."
    elif error_code == ERROR_HTTP:
        content = "Http Error. [%s]. Please check if other " \
                  "services are running on this port." % content
    elif error_code == ERROR_CONNECTION:
        content = "Connection Error. [%s]. Please check your " \
                  "configuration." % content
    elif error_code == ERROR_CLIENT:
        content = "Client error. [%s]. Please contact us. " \
                  "services are running on this port." % content
    else:
        content = "Unknown Error. %s" % content
    return error_code, content


def get_root_domain(app_url):
    parsed_uri = urlparse(app_url)
    domain = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
    return domain


def get_host(app_url):
    parsed_uri = urlparse(app_url)
    return parsed_uri.netloc


def resolve_url(url):
    parts = list(urlsplit(url))
    segments = parts[2].split('/')
    segments = [segment + '/' for segment in segments[:-1]] + [segments[-1]]
    resolved = []
    for segment in segments:
        if segment in ('../', '..'):
            if resolved[1:]:
                resolved.pop()
        elif segment not in ('./', '.'):
            resolved.append(segment)
    resolved = [part for part in resolved if part is not '/']
    parts[2] = ''.join(resolved)
    return urlunsplit(parts)


def _console_call_back(code, message):
    print " %s [%s] %s " % ('Request Result:', code, message)


def check_authorization(func):
    def wrapper(*args, **kwargs):
        request = args[0]
        if not isinstance(request, Request):
            return ERROR_CLIENT, \
                   '@check_authorization can be only used for Request.'
        error_code, message = request.validate_and_install_if_needed()
        if has_error(error_code):
            return error_code, message
        return func(*args, **kwargs)

    return wrapper


def async(func):
    def wrapper(*args, **kwargs):
        call_back = kwargs['call_back']
        if call_back is None:
            return func(*args, **kwargs)

        def run():
            error_code, message = func(*args, **kwargs)
            call_back(error_code, message)

        threat = Thread(target=run)
        threat.daemon = True
        threat.start()

    return wrapper


class Request:
    def __init__(self, validation_url, login_url, username, password,
                 session_identifier='JSESSIONID'):
        self.validation_url = validation_url
        self.login_url = login_url
        self.session_identifier = session_identifier
        self.username = username
        self.password = password
        self.session = None
        self.opener = None

    def _is_login_url(self, url_or_response):
        url = url_or_response \
            if isinstance(url_or_response, basestring) \
            else url_or_response.geturl()
        return resolve_url(self.login_url).lower() in resolve_url(url).lower()

    def _get_session_id(self):
        try:
            login_url = resolve_url(self.login_url)
            data = {'username': self.username, 'password': self.password}
            post_data = urllib.urlencode(data)
            cj = cookielib.MozillaCookieJar()
            opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
            self.opener = opener
            req = urllib2.Request(login_url, post_data, {
                "User-agent": "Kam1n0-py/2.0.0"})
            response = opener.open(req)
            if not self._is_login_url(response):
                for cookie in cj:
                    if cookie.name == self.session_identifier:
                        self.session = cookie.value
                        return OK, cookie.value
            return ERROR_LOGIN, ''
        except urllib2.HTTPError, e:
            return ERROR_HTTP, "Error: " + str(e.code)
        except urllib2.URLError, e:
            return ERROR_CONNECTION, e.reason
        except Exception as e:
            return ERROR_CONNECTION, e.message

    def _install_session_id(self):
        cj = cookielib.MozillaCookieJar()
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
        cookie = cookielib.Cookie(
            version=0,
            name=self.session_identifier,
            value=self.session,
            port=None,
            port_specified=False,
            domain='',
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
        cj.set_cookie(cookie)
        self.opener = opener

    def _do_get(self, url, params=None):
        try:
            request = url
            if params is not None:
                request = request + "?" + urllib.urlencode(params)
            response = self.opener.open(fullurl=request)
            content = response.read()
        except urllib2.HTTPError, e:
            return ERROR_HTTP, "Error: " + str(e.code)
        except urllib2.URLError, e:
            return ERROR_CONNECTION, e.reason
        except Exception as e:
            return ERROR_CONNECTION, e.message
        if self._is_login_url(response):
            return ERROR_LOGIN, content
        else:
            return OK, content

    def _do_post(self, url, data):
        try:
            post_data = urllib.urlencode(data)
            response = self.opener.open(fullurl=url, data=post_data)
            content = response.read()
        except urllib2.HTTPError, e:
            return ERROR_HTTP, "Error: " + str(e.code)
        except urllib2.URLError, e:
            return ERROR_CONNECTION, e.reason
        except Exception as e:
            return ERROR_CONNECTION, e.message
        if self._is_login_url(response):
            return ERROR_LOGIN, content
        else:
            return OK, content

    def validate_and_install_if_needed(self):
        if self.session is None:
            self._get_session_id()
        first_code, first_message = self._do_get(self.validation_url)
        if has_error(first_code):
            self._get_session_id()
            return self._do_get(self.validation_url)
        return first_code, first_message

    @async
    @check_authorization
    def ajax_post(self, url, data, call_back=_console_call_back):
        return self._do_post(url, data)

    @async
    @check_authorization
    def ajax_get(self, url, data, call_back=_console_call_back):
        return self._do_get(url, data)

    @async
    @check_authorization
    def show_post(self, url, data, external=None,
                  call_back=_console_call_back, queue=None):
        try:
            RequestPage.create_form_process(
                request_url=url,
                request_method='post',
                request_param=data,
                external_data=external,
                session=self.session,
                queue=queue
            )
        except Exception as e:
            return ERROR_CLIENT, e.message
        return OK, ""

    @async
    @check_authorization
    def show_get(self, url, data=None, external=None,
                 call_back=_console_call_back, queue=None):
        try:
            RequestPage.create_form_process(
                request_url=url,
                request_method='get',
                request_param=data,
                external_data=external,
                session=self.session,
                queue=queue
            )
        except Exception as e:
            return ERROR_CLIENT, e.message
        return OK, ""
