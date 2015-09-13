__author__ = 'jerrico'

from unittest import TestCase

import requests_mock

from phishnetpy import PhishNetAPI
from phishnetpy.exceptions import AuthError, PhishNetAPIError


class TestPhishNetAPI(TestCase):
    @staticmethod
    def register_mock(pnet_api):
        adapter = requests_mock.Adapter()
        pnet_api.session.mount('mock', adapter)
        return pnet_api, adapter

    def test_init(self):
        base_url_test = PhishNetAPI(base_url='https://api.notphish.net')
        self.assertEqual(base_url_test.base_url, 'https://api.notphish.net/')
        base_url_test = PhishNetAPI(base_url='https://api.notphish.net/')
        self.assertEqual(base_url_test.base_url, 'https://api.notphish.net/')

    def test_default_usename(self):
        username_test = PhishNetAPI(api_key='foo')
        with requests_mock.mock() as m:
            m._adapter.register_uri('GET', 'https://api.phish.net/api.json', [
                {'text': '{"success": "1"}', 'status_code': 200},
                {'text': '{"success": "1", "authkey": "232342342342"}', 'status_code': 200}
            ])
            username_test.authorize('wilson')

        self.assertEqual(username_test._default_username('suzy'), 'suzy')
        self.assertEqual(username_test._default_username(None), 'wilson')
        username_test = PhishNetAPI(api_key='foo')
        self.assertEqual(username_test._default_username('suzy'), 'suzy')
        self.assertRaises(TypeError, username_test._default_username, None)

    def test_fetch_auth_key(self):
        fak = PhishNetAPI(api_key='foo')
        with requests_mock.mock() as m:
            m._adapter.register_uri('GET', 'https://api.phish.net/api.json', [
                {'text': '{"success": "0"}', 'status_code': 200},
            ])
            self.assertRaises(AuthError, fak.fetch_auth_key, 'wilson')
        with requests_mock.mock() as m:
            m._adapter.register_uri('GET', 'https://api.phish.net/api.json', [
                {'text': '{"success": "0"}', 'status_code': 200},
            ])
            m._adapter.register_uri('POST', 'https://api.phish.net/api.json', [
                {'text': '{"success": "1", "authkey": "232342342342"}', 'status_code': 200}
            ])
            self.assertEqual('232342342342', fak.fetch_auth_key('wilson', 'password'))

    def test_api_authorize(self):
        aa_test = PhishNetAPI(api_key='foo')
        with requests_mock.mock() as m:
            m._adapter.register_uri('POST', 'https://api.phish.net/api.json', [
                {'text': '{"success": "0"}', 'status_code': 200},
            ])
            self.assertRaises(AuthError, aa_test.api_authorize, 'wilson', 'password')

    def test_authkey_get(self):
        autkey_get_test = PhishNetAPI()
        self.assertRaises(AuthError, autkey_get_test.authkey_get, 'wilson')
        autkey_get_test = PhishNetAPI(api_key='foo')
        with requests_mock.mock() as m:
            m._adapter.register_uri('GET', 'https://api.phish.net/api.json', [
                {'text': '{"success": "0"}', 'status_code': 200},
            ])
            self.assertEqual(False, autkey_get_test.authkey_get('wilson'))

    def test_query(self):
        query_test = PhishNetAPI(api_key='foo')
        self.assertRaises(NotImplementedError, query_test._query, 'PUT', 'foo')
        with requests_mock.mock() as m:
            m._adapter.register_uri('GET', 'https://api.phish.net/foo', [
                {'text': '{"success": "0"}', 'status_code': 500},
            ])
            self.assertRaises(PhishNetAPIError, query_test._query, 'GET', 'foo', None, 0)
        with requests_mock.mock() as m:
            m._adapter.register_uri('GET', 'https://api.phish.net/foo', [
                {'text': '{"success": "0"}', 'status_code': 500},
            ])
            m._adapter.register_uri('GET', 'https://api.phish.net/foo', [
                {'text': '{"success": "0"}', 'status_code': 500},
            ])
            m._adapter.register_uri('GET', 'https://api.phish.net/foo', [
                {'text': '{"success": "0"}', 'status_code': 200},
            ])
            self.assertEqual(200, query_test._query('GET', 'foo', data=None, retry=3).status_code)

    def test_parse_date(self):
        from datetime import date
        self.assertEqual(date.today(), PhishNetAPI.parse_date(date.today()))
        self.assertEqual(date.today(), PhishNetAPI.parse_date(str(date.today())))
        self.assertRaises(ValueError, PhishNetAPI.parse_date, 'sdkjwkrjw4kr')