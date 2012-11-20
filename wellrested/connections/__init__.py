import base64
import httplib2
import logging
import mimetypes
import mimetools
import urllib, urllib2
import cookielib
import urlparse
import os, time, stat
import getpass

HTTP_STATUS_OK = '200'

logger = logging.getLogger(__name__)


class RestClient(object):
    content_type = None

    def __init__(self, base_url, username=None, password=None,
                 connection_class=None, **kwargs):
        if connection_class is None:
            connection_class = Connection
        self._connection = connection_class(base_url, username, password,
                                            **kwargs)

    def get(self, resource, args=None, data=None, headers=None):
        return self._request(resource, 'get', args=args, data=data,
                             headers=headers)

    def put(self, resource, args=None, data=None, headers=None):
        return self._request(resource, 'put', args=args, data=data,
                             headers=headers)

    def delete(self, resource, args=None, data=None, headers=None):
        return self._request(resource, 'delete', args=args, data=data,
                             headers=headers)

    def post(self, resource, args=None, data=None, headers=None):
        return self._request(resource, 'post', args=args, data=data,
                             headers=headers)

    def _request(self, resource, method, args=None, data=None, headers=None):
        response_data = None
        request_body = self._serialize(data)
        try:
            response = self._connection.request(resource, method, args=args,
                body=request_body, headers=headers,
                content_type=self.content_type)
            response_content = response.read()
        except Exception as e:
            if (hasattr(e,"code") and e.code == 403):
                if (os.path.isfile(os.path.expanduser("~/.ocu"))):
                    os.remove(os.path.expanduser("~/.ocu"))
            raise e

        response_headers = response.info().items()
        if response.code == 200:
            response_data = self._deserialize(response_content)
        return Response(response_headers, response_content, response_data,status_code=response.code)

    def _serialize(self, data):
        return unicode(data)

    def _deserialize(self, data):
        return unicode(data)


class JsonRestClient(RestClient):
    content_type = 'application/json'

    def _serialize(self, data):
        if data:
            try:
                import simplejson as json
            except ImportError:
                try:
                    import json
                except ImportError:
                    raise RuntimeError('simplejson not installed')

            return json.dumps(data)
        return None

    def _deserialize(self, data):
        if data:
            try:
                import simplejson as json
            except ImportError:
                try:
                    import json
                except ImportError:
                    raise RuntimeError('simplejson not installed')

            return json.loads(data)
        return None


class XmlRestClient(RestClient):
    content_type = 'text/xml'


class Response(object):
    def __init__(self, headers, content, data, status_code=500):
        self.headers = headers
        self.content = content
        self.data = data
        self.status_code = int(status_code)

    def __repr__(self):
        return '<Response %s: %s>' % (self.status_code, self.__dict__)


class BaseConnection(object):
    def __init__(self, base_url, username=None, password=None):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.url = urlparse.urlparse(base_url)
        (scheme, netloc, path, query, fragment) = urlparse.urlsplit(base_url)
        self.scheme = scheme
        self.host = netloc
        self.path = path

    def _get_content_type(self, filename):
        return mimetypes.guess_type(filename)[0] or 'application/octet-stream'

    def request(self, resource, method="get", args=None, body=None,
                headers=None, content_type=None):
        raise NotImplementedError


class Connection(BaseConnection):
    _headers={}
    _csrf_token = None
    _token = None

    def __init__(self, *args, **kwargs):
        cache = kwargs.pop('cache', None)
        timeout = kwargs.pop('cache', None)
        proxy_info = kwargs.pop('proxy_info', None)
        login_url = kwargs.pop('login_url', None)
        token = kwargs.pop('token', None)

        super(Connection, self).__init__(*args, **kwargs)

        #remove cookie if it's older than an hour
        if (os.path.isfile(os.path.expanduser("~/.ocu"))
                and (time.time() - os.stat(os.path.expanduser("~/.ocu"))[stat.ST_MTIME]) > 3600):
            os.remove(os.path.expanduser("~/.ocu"))

        cj = cookielib.LWPCookieJar()

        if (login_url and os.path.isfile(os.path.expanduser("~/.ocu"))):
            cj.load(os.path.expanduser("~/.ocu"))

        self._conn = urllib2.build_opener(
            urllib2.HTTPCookieProcessor(cj), 
            urllib2.HTTPHandler(debuglevel=0)
        )

        #API token
        if (token):
            self._token = token

        if (login_url and not os.path.isfile(os.path.expanduser("~/.ocu"))):
            username = getpass.getuser()
            password = getpass.getpass()
            from lxml import html
            login_form = self._conn.open(login_url).read()
            self._csrf_token = html.fromstring(login_form).xpath(
                '//input[@name="csrfmiddlewaretoken"]/@value')[0]
            values = {
                'this_is_the_login_form': 1,
                'username': username,
                'password': password,
                'csrfmiddlewaretoken': self._csrf_token,
                'next': '/admin/'
            }
            params = urllib.urlencode(values)
            login_page = self._conn.open(login_url, params)
            
            cj.save(os.path.expanduser("~/.ocu"))
            os.chmod(os.path.expanduser("~/.ocu"),0600)
        else:
            for i in cj:
                if (i.name == "csrftoken"):
                    self._csrf_token = i.value

    def request(self, resource, method, args=None, body=None, headers=None,
                content_type=None):
        if headers is None:
            headers = {}
        if (self._headers):
            headers = dict(headers.items() + self._headers.items())

        params = None
        path = resource
        headers['User-Agent'] = 'Basic Agent'

        BOUNDARY = mimetools.choose_boundary()
        CRLF = u'\r\n'

        if body:
            if not headers.get('Content-Type', None):
                headers['Content-Type'] = content_type or 'text/plain'
            headers['Content-Length'] = str(len(body))
        else:
            if 'Content-Length' in headers:
                del headers['Content-Length']

            headers['Content-Type'] = 'text/plain'

            if args:
                if (self._token):
                    args["token"] = self._token
                if method == "get":
                    path += u"?" + urllib.urlencode(args)
                elif method == "put" or method == "post":
                    if (isinstance(args, dict) and self._csrf_token):
                        headers["X-CSRFToken"] = self._csrf_token
                        #args["csrfmiddlewaretoken"] = self._csrf_token
                    headers['Content-Type'] = \
                        'application/x-www-form-urlencoded'
                    body = urllib.urlencode(args)

        if (method == "delete"):
            headers["X-CSRFToken"] = self._csrf_token

        request_path = []
        # Normalise the / in the url path
        if self.path != "/":
            if self.path.endswith('/'):
                request_path.append(self.path[:-1])
            else:
                request_path.append(self.path)
            if path.startswith('/'):
                request_path.append(path[1:])
            else:
                request_path.append(path)
        url = u"%s://%s%s" % (self.scheme, self.host,u'/'.join(request_path))

        request = urllib2.Request(url,headers=headers,data=body)
        if (method == "delete"):
            request.get_method = lambda: 'DELETE'
        if (self._token):
            request.add_header("X-Auth-Token", "{0}".format(self._token))
        return self._conn.open(request)

