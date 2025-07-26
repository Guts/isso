# -*- encoding: utf-8 -*-

import json
import os
import re
import tempfile
import unittest
from unittest.mock import patch

from urllib.parse import urlencode
from urllib.request import Request, urlopen

from werkzeug.wrappers import Response

from isso import Isso, core, config
from isso.utils import http
from isso.views import comments

from fixtures import curl, loads, FakeIP, FakeHost, JSONClient
http.curl = curl

class TestNotifications(unittest.TestCase):

    def setUp(self):
        fd, self.path = tempfile.mkstemp()
        conf = config.load(config.default_file())
        conf.set("general", "dbpath", self.path)
        conf.set("general", "notify", "webhook")
        conf.set("guard", "enabled", "off")
        conf.set("hash", "algorithm", "none")
        conf.set("webhook", "latest-enabled", "true")
        self.conf = conf

        class App(Isso, core.Mixin):
            pass

        self.app = App(conf)
        self.app.wsgi_app = FakeIP(self.app.wsgi_app, "192.168.1.1")

        self.client = JSONClient(self.app, Response)
        self.get = self.client.get
        self.put = self.client.put
        self.post = self.client.post
        self.delete = self.client.delete

    def tearDown(self):
        os.unlink(self.path)

    @patch("urlopen")
    def test_webhook_no_template(self, mock_post):
        pass
        # info = {"test1": "value1", "test2": "value2"}
        # resp = requests.post("www.someurl.com", data=json.dumps(info), headers={'Content-Type': 'application/json'})
        # mock_post.assert_called_with("www.someurl.com", data=json.dumps(info), headers={'Content-Type': 'application/json'})


        # self.post('/new?uri=%2Fpath%2F',
        #           data=json.dumps({'text': 'Lorem ipsum ...'}))
        # r = self.get('/id/1')
        # self.assertEqual(r.status_code, 200)

        # rv = loads(r.data)

        # self.assertEqual(rv['id'], 1)
        # self.assertEqual(rv['text'], '<p>Lorem ipsum ...</p>')
