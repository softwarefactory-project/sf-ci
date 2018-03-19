import config
import requests

from utils import get_cookie


def assign_cookies():
    for k, v in config.USERS.items():
        v['auth_cookie'] = get_cookie(k,
                                      v['password'])


def assign_apikey():
    for user in ("user2", ):
        v = config.USERS[user]
        cookie = {'auth_pubtkt': v['auth_cookie']}
        if not cookie['auth_pubtkt']:
            continue
        r = requests.get(config.GATEWAY_URL + "/auth/apikey/", cookies=cookie)
        if r.status_code != 200:
            r = requests.post(config.GATEWAY_URL + "/auth/apikey/",
                              cookies=cookie)
        v['api_key'] = r.json()['api_key']


def setup():
    assign_cookies()
    assign_apikey()
