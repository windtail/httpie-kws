"""
AWS auth plugin for HTTPie.

"""
import os
import sys

from httpie.status import ExitStatus
from httpie.plugins import AuthPlugin
import hashlib
from datetime import datetime, timezone
from urllib3.util import parse_url

__version__ = '1.0.0'
__author__ = 'Luo Jiejun'
__licence__ = 'Apache'

KEY = 'KWS_APP_ID'
SECRET = 'KWS_APP_SECRET'


class KwsAppAuth:
    def __init__(self, app_id, app_secret):
        self.app_id = app_id
        self.app_secret = app_secret

    @staticmethod
    def hash_data(data: bytes):
        md5sign = hashlib.md5()
        md5sign.update(data)
        return md5sign.hexdigest()

    @staticmethod
    def hash_signature(sig: str):
        return KwsAppAuth.hash_data(sig.encode('utf-8'))

    def __call__(self, r):
        uri = parse_url(r.url)
        host = uri.host

        body = r.body
        if body is None:
            content_md5 = 'd41d8cd98f00b204e9800998ecf8427e'
        else:
            content_md5 = self.hash_data(body)

        now = datetime.now(tz=timezone.utc).isoformat()
        date = now
        signature = host + date + content_md5 + self.app_secret
        credential = self.app_id + '/' + now

        r.headers.update({'Authorization': 'KND-MD5 '
                                           'Credential=%s '
                                           'SignedHeaders=host;x-knd-date;x-knd-content-md5 '
                                           'Signature=%s' % (credential, self.hash_signature(signature)),
                          'X-Knd-Date': date,
                          'X-Knd-Content-MD5': content_md5})

        return r


class KwsAuthPlugin(AuthPlugin):
    name = 'KWS auth'
    auth_type = 'kws'
    description = ''
    auth_require = False
    prompt_password = True

    def get_auth(self, username=None, password=None):
        # There's a differences between None and '': only use the
        # env vars when --auth, -a not specified at all, otherwise
        # the behaviour would be confusing to the user.
        app_id = os.environ.get(KEY) if username is None else username
        app_secret = os.environ.get(SECRET) if password is None else password
        if not app_id or not app_secret:
            missing = []
            if not app_id:
                missing.append(KEY)
            if not app_secret:
                missing.append(SECRET)
            sys.stderr.write(
                'httpie-kws-auth error: missing {1}\n'
                    .format(self.name, ' and '.join(missing))
            )
            sys.exit(ExitStatus.PLUGIN_ERROR)

        return KwsAppAuth(app_id, app_secret)
