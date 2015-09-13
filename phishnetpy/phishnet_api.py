__author__ = 'jerrico'

from datetime import date
import arrow

from phishnetpy.exceptions import *
from phishnetpy.decorators import check_api_key, check_authorized_user

import requests


class PhishNetAPI(object):
    DEFAULT_VERSION = '2.0'
    DEFAULT_RETRY = 3
    FORMAT = 'json'

    def __init__(self, api_key=None, base_url='https://api.phish.net/', version=DEFAULT_VERSION,
                 verify_ssl_certificate=True, timeout=60, auth_key=None):
        """
        :param api_key: Your application's pre-assigned API key. This parameter is not required for public API
            methods but is required to call any protected API methods.
        :param base_url: The base URL to invoke API calls from.  Defaults the the standard phish.net API base.
        :param version: A string with the API version. This method targets version 2.0. If you do not pass this variable
            it will default to the current version of the API, which may yield unexpected results. The current version
            is '2.0'.
        :param verify_ssl_certificate: Typically this should be set to true, but remains as an optional parameter, in
            case there are ever future issues with the Phish.net SSL sertificate.  Setting this to False will allow
            requests to be made even if the SSL certificate is invalid.
         :param timeout: The maximum time (in seconds) that the API client should wait for a response before considering
            it to be a failure and moving on.  You may set this to None to disable this behavior altogether.
         :param auth_key: The authorization key previously retrieved for a user.  If one has not been generated or is
            not known, it may be generated via the authorize method.
        """
        self.api_key = api_key
        if not base_url.endswith('/'):
            self.base_url = base_url + '/'
        else:
            self.base_url = base_url
        self.version = version
        self.verify_ssl_certificate = verify_ssl_certificate
        self.timeout = timeout
        self.session = requests.session()
        self.username = None
        self.auth_key = auth_key

    def _default_username(self, username):
        u = username or self.username
        if not u:
            raise TypeError('username is required.')
        return u

    def authorize(self, username, password=None):
        """ Authorize the current instance to be able to make privileged` API calls on behalf of a selected user. In
            order to use this method, you must have passed an API key into the constructor method.  Failure to do so
            will result in an AuthError exception.
        :param username: The username to authorize on behalf of.
        :param password: The password of that user.  Password is only required if this is the first time that user is
            being authorized against this API key.
        """
        self.auth_key = self.fetch_auth_key(username, password)
        self.username = username

    def fetch_auth_key(self, username, password=None):
        """
        This method will handle negotiation of the authorization for a user.  In order to use this method, you must
            have passed an API key into the constructor method.  Failure to do so will result in an AuthError exception.
            Three main scenarios
        :param username: The username to authorize on behalf of.
        :param password: The password of that user.  Password is only required if this is the first time that user is
            being authorized against this API key.
        """

        if self.authorized_check(username):
            a = self.authkey_get(username)
        else:
            if not password:
                raise AuthError(
                    'User {} was not previously authorized and no password was provided'.format(username))
            else:
                a = self.api_authorize(username, password)
        return a

    @check_api_key
    def api_authorize(self, username, password):
        params = {
            'method': 'pnet.api.authorize',
            'username': username,
            'passwd': password
        }
        response = self.post(params=params)
        if not response.get('success'):
            raise AuthError("Auth attempt unsuccessful.")
        else:
            return response['authkey']

    @check_api_key
    def authorized_check(self, username):
        params = {
            'method': 'pnet.api.authorized.check',
            'username': username,
        }
        response = self.get(params=params)
        return response.get('success') == True

    @check_api_key
    def authkey_get(self, username):
        if not self.api_key:
            raise AuthError("Authorization key get made without API key")
        params = {
            'method': 'pnet.api.authkey.get',
            'username': username,
        }
        response = self.get(params=params)
        if response.get('success'):
            return response['authkey']
        else:
            return False

    def blog_get(self):
        return self.get(params={'method': 'pnet.blog.get', 'format': self.FORMAT})

    def blog_item_get(self, id):
        return self.get(params={'method': 'pnet.blog.item.get', 'id': id, 'format': self.FORMAT})

    def forum_get(self):
        return self.get(params={'method': 'pnet.forum.get', 'format': self.FORMAT})

    @check_api_key
    def forum_thread_get(self, thread):
        return self.get(params={'method': 'pnet.forum.thread.get', 'thread': thread, 'format': self.FORMAT})

    @check_api_key
    def forum_canpost(self, username=None):
        return self.get(
            params={'method': 'pnet.forum.canpost', 'username': self._default_username(username)}
        )

    @check_authorized_user
    def forum_thread_new(self, title, txt):
        return self.post(
            params={
                'method': 'pnet.forum.thread.new', 'username': self.username, 'title': title, 'txt': txt,
                'authkey': self.auth_key
            }
        )

    @check_authorized_user
    def forum_thread_respond(self, thread, txt):
        return self.post(
            params={
                'method': 'pnet.forum.thread.new', 'username': self.username, 'thread': thread, 'txt': txt,
                'authkey': self.auth_key
            }
        )

    def news_get(self):
        return self.get(params={'method': 'pnet.news.get', 'format': self.FORMAT})

    def news_comments_get(self):
        return self.get(params={'method': 'pnet.news.comments.get', 'format': self.FORMAT})

    def reviews_recent(self):
        return self.get(params={'method': 'pnet.reviews.recent', 'format': self.FORMAT})

    @check_api_key
    def reviews_query(self, username=None, showdate=None):
        params = {'method': 'pnet.reviews.query', 'format': self.FORMAT}
        if username:
            params['username'] = username
        if showdate:
            params['showdate'] = str(self.parse_date(showdate))
        return self.get(params=params)

    def shows_setlists_latest(self, linked=True):
        params = {'method': 'pnet.shows.setlists.latest', 'format': self.FORMAT}
        if not linked:
            params['linked'] = -1
        return self.get(params=params)

    def shows_setlists_random(self):
        return self.get(params={'method': 'pnet.shows.setlists.random', 'format': self.FORMAT})

    def shows_setlists_recent(self):
        return self.get(params={'method': 'pnet.shows.setlists.recent', 'format': self.FORMAT})

    @check_api_key
    def shows_setlists_get(self, showid=None, showdate=None):
        params = {'method': 'pnet.shows.setlists.get', 'format': self.FORMAT}
        if showid:
            params['showid'] = showid
        if showdate:
            params['showdate'] = str(self.parse_date(showdate))
        return self.get(params=params)

    def shows_setlists_tiph(self):
        return self.get(params={'method': 'pnet.shows.setlists.tiph', 'format': self.FORMAT})

    @check_api_key
    def shows_links_get(self, showid):
        return self.get(params={'method': 'pnet.shows.links.get', 'format': self.FORMAT, 'showid': showid})

    def shows_upcoming(self):
        return self.get(params={'method': 'pnet.shows.upcoming', 'format': self.FORMAT})

    @check_api_key
    def shows_query(self, year=None, venueid=None, state=None, country=None, month=None, day=None, artist=None,
                    showids=None):
        l = locals().copy()
        l.pop('self')
        params = {'method': 'pnet.shows.query', 'format': self.FORMAT}
        for k, v in l.items():
            if v:
                if k == 'showids' and isinstance(v, list):
                    params[k] = ','.join([str(x) for x in v])
                else:
                    params[k] = v
        return self.get(params=params)

    @check_api_key
    def collections_get(self, collectionid):
        return self.get(params={'method': 'pnet.collections.get', 'format': self.FORMAT, 'collectionid': collectionid})

    @check_api_key
    def collections_query(self, uid):
        return self.get(params={'method': 'pnet.collections.query', 'format': self.FORMAT, 'uid': uid})

    @check_api_key
    def user_username_check(self, username):
        return self.get(params={'method': 'pnet.user.username.check', 'format': self.FORMAT, 'username': username})

    @check_api_key
    def user_register(self, username, password, email, realname):
        return self.post(params={
            'method': 'pnet.user.username.check', 'format': self.FORMAT,
            'username': username, 'password': password, 'email': email, 'realname': realname}
        )

    @check_api_key
    def user_get(self, uid):
        return self.get(params={'method': 'pnet.user.get', 'format': self.FORMAT, 'uid': uid})

    @check_api_key
    def user_uid_get(self, username):
        return self.get(params={'method': 'pnet.user.uid.get', 'format': self.FORMAT, 'username': username})

    @check_api_key
    def user_myshows_get(self, usernames):
        params = {'method': 'pnet.user.myshows.get', 'format': self.FORMAT}
        if isinstance(usernames, list):
            params['usernames'] = ','.join([str(u) for u in usernames])
        elif isinstance(usernames, str):
            if ',' in usernames:
                params['usernames'] = usernames
            else:
                params['username'] = usernames
        return self.get(params=params)

    @check_authorized_user
    def user_myshows_get_authorized(self):
        params = {
            'method': 'pnet.user.myshows.get', 'username': self.username, 'authkey': self.auth_key,
            'format': self.FORMAT
        }
        return self.get(params=params)

    @check_authorized_user
    def user_myshows_add(self, showdate):
        params = {
            'method': 'pnet.user.myshows.add', 'username': self.username, 'authkey': self.auth_key,
            'showdate': str(self.parse_date(showdate))
        }
        return self.post(params=params)

    @check_authorized_user
    def user_myshows_remove(self, showdate):
        params = {
            'method': 'pnet.user.myshows.remove', 'username': self.username, 'authkey': self.auth_key,
            'showdate': str(self.parse_date(showdate))
        }
        return self.post(params=params)

    @check_authorized_user
    def user_myshows_add(self, showdate):
        params = {
            'method': 'pnet.user.myshows.add', 'username': self.username, 'authkey': self.auth_key,
            'showdate': str(self.parse_date(showdate))
        }
        return self.post(params=params)

    @check_authorized_user
    def user_shows_rate(self, showdate, rating):
        try:
            valid_rating = int(rating) in range(1, 6)
        except ValueError:
            valid_rating = False
        if not valid_rating:
            raise ValueError('Invalid rating {}. Rating must be an integer between 1 and 5'.format(rating))
        params = {
            'method': 'pnet.user.shows.rate', 'username': self.username, 'authkey': self.auth_key,
            'showdate': str(self.parse_date(showdate)), 'rating': int(rating)
        }
        return self.post(params=params)

    def jamcharts_all(self):
        return self.get(params={'method': 'pnet.jamcharts.all'})

    def artists_get(self):
        return self.get(params={'method': 'pnet.artists.get', 'format': self.FORMAT})

    def get(self, path='api.json', retry=DEFAULT_RETRY, params=None):
        """
        Get an item from the Phish.net API.
        :param path: The path to call.  The path is appended to the base URL.  Typically on Phish.net API, this is
            'api.js', the default value.
        :param retry: An integer describing how many times the request may be retried.
        :param params: A dictionary of HTTP GET parameters (for GET requests)
        """
        response = self._query('GET', path, data=params, retry=retry)

        if not response:
            raise PhishNetAPIError('Unable to retrieve HTTP GET {}'.format(path))
        return response.json()

    def post(self, path='api.json', retry=DEFAULT_RETRY, params=None):
        """
        Get an item from the Phish.net API.
        :param path: The path to call.  The path is appended to the base URL.  Typically on Phish.net API, this is
            'api.js', the default value.
        :param retry: An integer describing how many times the request may be retried.
        :param params: A dictionary of HTTP POST data (for POST requests).
        """
        response = self._query('POST', path, data=params, retry=retry)

        if not response:
            raise PhishNetAPIError('Unable to retrieve HTTP POST {}'.format(path))
        return response.json()

    def _query(self, method, path, data=None, retry=0):
        """
        :param method: HTTP method to query the API.  Typically for Phish.net only GET or POST
        :param path: The path to call.  The path is appended to the base URL.  Typically on Phish.net API, this is
            'api.js'
        :param data: A dictionary of HTTP GET parameters (for GET requests) or POST data (for POST requests).
        :param retry: An integer describing how many times the request may be retried.
        """

        url = self.base_url + path
        data = data or {}
        data['api'] = self.version
        if self.api_key:
            data['apikey'] = self.api_key

        def load(method, url, data):
            try:
                if method == 'GET':
                    response = self.session.request(
                        method, url, params=data, allow_redirects=True,
                        verify=self.verify_ssl_certificate, timeout=self.timeout
                    )

                elif method == 'POST':
                    response = self.session.request(
                        method, url, data=data, verify=self.verify_ssl_certificate, timeout=self.timeout
                    )
                else:
                    raise NotImplementedError("Phish.net API only supports HTTP GET or POST.")

                if 500 <= response.status_code < 600:
                    raise PhishNetAPIError(
                        'Internal Phish.net API error occurred',
                        response.status_code
                    )

            except requests.RequestException as exception:
                raise HTTPError(exception)
            return response

        try:
            return load(method, url, data)
        except PhishNetAPIError:
            if retry:
                return self._query(method, path, data, retry - 1)
            else:
                raise

    @staticmethod
    def parse_date(d):
        if isinstance(d, date):
            return d
        else:
            try:
                d = arrow.get(d).date()
            except arrow.parser.ParserError:
                raise ValueError('Showdate {} could not be parsed into a date. Use YYYY-MM-DD format.'.format(d))
            return d
