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
        """ Return either the username or authorized username if username is none.
        :param username: The username requested in another API method.  If none attempt to use self.username
        :rtype : str
        """
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
        """
        Grants "write access" to an application for a particular user.
        :param username: The user's phish.net username
        :param password: The user's phish.net password
        :return: API response object.  On success, the variable "success" will be set to 1, and the variable "authkey"
            will contain the user's 19 digit hexadecimal string application authorization key.
        :raise AuthError: Raised when the auth attempt does not succeed.
        """
        params = {
            'method': 'pnet.api.authorize',
            'username': username,
            'passwd': password
        }
        response = self.post(params=params)
        if not str(response.get('success')) == '1':
            raise AuthError("Auth attempt unsuccessful.")
        else:
            return response['authkey']

    @check_api_key
    def authorized_check(self, username):
        """
        Determines whether or not a user has authorized write access for an application.
        :param username: The user's phish.net username
        :return: API response object.  "success" set to 1 if the app is authorized, or "success" set to 0 if not.

        """
        params = {
            'method': 'pnet.api.authorized.check',
            'username': username,
        }
        response = self.get(params=params)
        return str(response.get('success')) == '1'

    @check_api_key
    def authkey_get(self, username):
        """
        Retrieves the authkey of a user who has already authorized your application.
        :param username: The user's phish.net username
        :return: API response object. On success, the variable "success" will be set to 1, and the variable "authkey"
            will contain the user's 19 digit hexadecimal string application authorization key. On failure, or if the
            app is not authorized, the method will return "success" set to 0.
        """
        params = {
            'method': 'pnet.api.authkey.get',
            'username': username,
        }
        response = self.get(params=params)
        if str(response.get('success')) == '1':
            return response['authkey']
        else:
            return False

    def blog_get(self):
        """
        Lists the title of recently posted entries to the phish.net blog.
        :return: API response object of recent blog entries.
        """
        return self.get(params={'method': 'pnet.blog.get', 'format': self.FORMAT})

    def blog_item_get(self, id):
        """
        Gets a single item from the Phish.net blog.
        :param id: The ID of the item you wish to receive.
        :return: API response object of blog entry.
        """
        return self.get(params={'method': 'pnet.blog.item.get', 'id': id, 'format': self.FORMAT})

    def forum_get(self):
        """
        Lists the title of recently active threads in the phish.net forum.
        :return: API response object of recent threads.
        """
        return self.get(params={'method': 'pnet.forum.get', 'format': self.FORMAT})

    @check_api_key
    def forum_thread_get(self, thread):
        """
        Returns the data in a thread in the phish.net forum.
        :param thread: The ID of the thread you wish to receive.
        :return: API response object of the thread.
        """
        return self.get(params={'method': 'pnet.forum.thread.get', 'thread': thread, 'format': self.FORMAT})

    @check_api_key
    def forum_canpost(self, username=None):
        """
        Verifies that a user can post to the phish.net forum.
        :param username: The user's phish.net username.  If none, will default to the username of the currently
            authorized used.
        :return: API response object. "canpost" is either 1 for true 0 for false, and if false, "reason" will return the
            reason a user cannot post.
        """
        return self.get(
            params={'method': 'pnet.forum.canpost', 'username': self._default_username(username)}
        )

    @check_authorized_user
    def forum_thread_new(self, title, txt):
        """ Start a new thread on the phish.net forum.
        :param title: The title of the new forum thread. Max: 255 characters.
        :param txt: The body of the forum post. URL encoded, max: 1024 characters
        :return: API response object. "success" is either 1 for true 0 for false, and if false, "reason" will return the
            reason a user cannot post. If true, "thread" will return the new thread id
        """
        return self.post(
            params={
                'method': 'pnet.forum.thread.new', 'username': self.username, 'title': title, 'txt': txt,
                'authkey': self.auth_key
            }
        )

    @check_authorized_user
    def forum_thread_respond(self, thread, txt):
        """ Respond to a thread on the phish.net forum.
        :param txt: The body of the forum post. URL encoded, max: 1024 characters
        :return: API response object. "success" is either 1 for true 0 for false. If false, "reason" will return the
            reason a user cannot post. If true, it will be blank.
        """
        return self.post(
            params={
                'method': 'pnet.forum.thread.respond', 'username': self.username, 'thread': thread, 'txt': txt,
                'authkey': self.auth_key
            }
        )

    def news_get(self):
        """
        Returns a list of recently posted news stories.
        :return: API response object of recent news stories.
        """
        return self.get(params={'method': 'pnet.news.get', 'format': self.FORMAT})

    def news_comments_get(self):
        """
        Returns a list of comments recently posted to news stories.
        :return: API response object of recent news story comments.
        """
        return self.get(params={'method': 'pnet.news.comments.get', 'format': self.FORMAT})

    def reviews_recent(self):
        """
        Returns a list of recently posted show reviews.
        :return: API response object of recent show reviews.
        """
        return self.get(params={'method': 'pnet.reviews.recent', 'format': self.FORMAT})

    @check_api_key
    def reviews_query(self, username=None, showdate=None):
        """
        Returns a list of recently posted reviews by a particular user or show date.
        :param username: If a username is provided, it will return reviews posted by a given user.
        :param showdate: Either a datetime.date or date string in YYYY-MM-DD format. If not None, it will return reviews
            attached to a given show. If both username and showdate are provided, it will filter by both showdate AND
            username.
        :return: API response object of show reviews.
        """
        params = {'method': 'pnet.reviews.query', 'format': self.FORMAT}
        if username:
            params['username'] = username
        if showdate:
            params['showdate'] = str(self.parse_date(showdate))
        return self.get(params=params)

    def shows_setlists_latest(self, linked=True):
        """
        Returns the most current full Phish setlist in our database.
        :param linked: This method returns the setlists linked to phish.net song histories. To override this, set linked
            to False, and setlist songs will not be linked, however, the setlist will contain "via phish.net" at the
            bottom.
        :return: API response object of show setlist.
        """
        params = {'method': 'pnet.shows.setlists.latest', 'format': self.FORMAT}
        if not linked:
            params['linked'] = -1
        return self.get(params=params)

    def shows_setlists_random(self):
        """
        Returns a random Phish setlist from our database.
        :return: API response object of show setlist.
        """
        return self.get(params={'method': 'pnet.shows.setlists.random', 'format': self.FORMAT})

    def shows_setlists_recent(self):
        """
        Returns several of the most recent Phish setlists in our database in descending order.
        :return: API response object of show setlists.
        """
        return self.get(params={'method': 'pnet.shows.setlists.recent', 'format': self.FORMAT})

    @check_api_key
    def shows_setlists_get(self, showid=None, showdate=None):
        """
        Returns the setlist of a given show.
        :param showid: showid is the integer showid of a given show
        :param showdate: Either a datetime.date or date string in YYYY-MM-DD format. If not None, it will return reviews
            attached to a given show. showdate is the a given show date, in YYYY-MM-DD format; You must pass either an
            showdate or a showid for this method to work. In case of conflict, the showid will win.
        :return: API response object of show setlists.
        """
        params = {'method': 'pnet.shows.setlists.get', 'format': self.FORMAT}
        if showid:
            params['showid'] = showid
        if showdate:
            params['showdate'] = str(self.parse_date(showdate))
        return self.get(params=params)

    def shows_setlists_tiph(self):
        """
        "Today In Phish History": returns the setlist of a show from the current day and month in Phish history.
        :return: API response object of show setlists.
        """
        return self.get(params={'method': 'pnet.shows.setlists.tiph', 'format': self.FORMAT})

    @check_api_key
    def shows_links_get(self, showid):
        """
        Returns a list of links associated with a show.
        :param showid: The showid of the show. Unlike other methods, this method only works with showid, not with
            showdate.
        :return: API response object of show links.
        """
        return self.get(params={'method': 'pnet.shows.links.get', 'format': self.FORMAT, 'showid': showid})

    def shows_upcoming(self):
        """
        Returns a list of up to 5 upcoming shows.
        :return: API response object of shows.
        """
        return self.get(params={'method': 'pnet.shows.upcoming', 'format': self.FORMAT})

    @check_api_key
    def shows_query(self, year=None, venueid=None, state=None, country=None, month=None, day=None, artist=None,
                    showids=None):
        """
        Returns a list of setlists that match certain criteria. You can pass one or more of the following arguments. If
            you do not pass any arguments, the method will return shows from the current year.
        :param year: If a 4 digit year is provided, it will return a list of shows attached to a year. Note that it will
            NOT return the setlists, only the shows.
        :param venueid: If a venueid integer is provided, it will return a list of shows attached to a given venue.
        :param state: If a 2 character string called state is provided, it will return a list of shows performed in a US state.
        :param country: If a country name is provided, it will return shows in a given country
        :param month: Provide an integer that is a 1 or 2 digit month to return shows in a given month
        :param day: Provide an integer that is a 1 or 2 digit day to return shows on a given day of the month
        :param artist: Provide an integer to represent an artist, defaults to "1", which is Phish. List can be pulled f
            rom pnet.artists.get
        :param showids: Provide a comma separated list of integers representing the showids of setlist you want to
            fetch. May either be a comma separated string or list.
        :return: API response object of show setlists.
        """
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
        """
        Returns a Phish.net "Collection"
        :param collectionid: A required integer
        :return: API response object of collection.
        """
        return self.get(params={'method': 'pnet.collections.get', 'format': self.FORMAT, 'collectionid': collectionid})

    @check_api_key
    def collections_query(self, uid):
        """
        Queries for a list of a given user's "collections"
        :param uid: a required integer of the user's user id
        :return: API response object of collection.
        """
        return self.get(params={'method': 'pnet.collections.query', 'format': self.FORMAT, 'uid': uid})

    @check_api_key
    def user_username_check(self, username):
        """
        Checks availability of a username at phish.net.
        :param username: the requested username
        :return: API response object. "success" is either 1 for true 0 for false. If false, "reason" will return the
            reason the username is not available. Note that sometimes, the name is invalid, and "reason" will explain
            why. If true, "reason" will be blank.
        """
        return self.get(params={'method': 'pnet.user.username.check', 'format': self.FORMAT, 'username': username})

    @check_api_key
    def user_register(self, username, password, email, realname):
        """ Registers a new account at phish.net.
        :param username: The requested username, required
        :param password: The user's password, required
        :param email: The user's email address, required
        :param realname: The new user's real name, urlencoded
        :return: API response object. "success": returns 1 for success, 0 for error, "uid:" user id, greater than 0 means
            success; "reason": on failure, a reason will be returned, "authkey": on successful registration, you'll also
            receive back an "authkey" to interact with account data. Registering with an app grants that app authority
            to your account. A user can then revoke this permission in their Phish.net application settings.
        """
        return self.post(params={
            'method': 'pnet.user.username.check', 'format': self.FORMAT,
            'username': username, 'password': password, 'email': email, 'realname': realname}
        )

    # @check_api_key
    # def user_get(self, uid):
    #     return self.get(params={'method': 'pnet.user.get', 'format': self.FORMAT, 'uid': uid})

    @check_api_key
    def user_uid_get(self, username):
        """
        Returns the user id for a user at phish.net.
        :param username: the username of the user
        :return: User id
        """
        return self.get(params={'method': 'pnet.user.uid.get', 'format': self.FORMAT, 'username': username})

    @check_api_key
    def user_myshows_get(self, usernames):
        """
        Retreives a list of shows a user has attended.
        :param usernames: May either be a single username, a comma seperated string of many usernames, or a list of
            usernames
        :return: API response object, showing shows per user
        """
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
        """
        Retreives a list of shows the authorized user has attended.
        :return: API response object, showing shows per user
        """
        params = {
            'method': 'pnet.user.myshows.get', 'username': self.username, 'authkey': self.auth_key,
            'format': self.FORMAT
        }
        return self.get(params=params)

    @check_authorized_user
    def user_myshows_add(self, showdate):
        """
        Add a show to the authorized user's list.
        :param showdate: Either a datetime.date or date string in YYYY-MM-DD format. If not None, it will return reviews
            attached to a given show. If both username and showdate are provided, it will filter by both showdate AND
            username.
        :return: API response object. "success" is either 1 for true 0 for false. If false, "reason" will return a
            reason. If true, it will be blank.
        """

        params = {
            'method': 'pnet.user.myshows.add', 'username': self.username, 'authkey': self.auth_key,
            'showdate': str(self.parse_date(showdate))
        }
        return self.post(params=params)

    @check_authorized_user
    def user_myshows_remove(self, showdate):
        """
        Remove a show from the authorized user's list.
        :param showdate: Either a datetime.date or date string in YYYY-MM-DD format. If not None, it will return reviews
            attached to a given show. If both username and showdate are provided, it will filter by both showdate AND
            username.
        :return: API response object. "success" is either 1 for true 0 for false. If false, "reason" will return a
            reason. If true, it will be blank.
        """
        params = {
            'method': 'pnet.user.myshows.remove', 'username': self.username, 'authkey': self.auth_key,
            'showdate': str(self.parse_date(showdate))
        }
        return self.post(params=params)

    @check_authorized_user
    def user_shows_rate(self, showdate, rating):
        """
        Add a rating to a show..
        :param showdate: Either a datetime.date or date string in YYYY-MM-DD format. If not None, it will return reviews
            attached to a given show. If both username and showdate are provided, it will filter by both showdate AND
            username.
        :param rating: integer between 1 and 5
        :return: An API Response object. "success" is either 1 for true 0 for false.
        :raise ValueError: If rating is invalid
        """
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
        """
        Returns jamchart data from phish.net.
        :return: An API response object describing Jam Charts.
        """
        return self.get(params={'method': 'pnet.jamcharts.all'})

    def artists_get(self):
        """
        Returns a list of artists supported by the API.
        :return: An API response object describing Artists.
        """
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
