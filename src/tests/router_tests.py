from nose.tools import ok_, eq_

try:
	from httplib import OK, PERMANENT_REDIRECT
except:
	from http.client import OK, PERMANENT_REDIRECT

from config import *
from application import application


base_url = '/api/v{0}'.format(API_VERSION)
application.testing = True
app = application.test_client()


def test_ddwrt_install_script_redirects():
	response = app.head('{}/ddwrt/group/default/provider/blackbox/install'.format(base_url))
	ok_(response.status_code == PERMANENT_REDIRECT)


def test_ddwrt_install_script_return_correct_header():
	response = app.head('/ddwrt')
	ok_(response.status_code == OK)
	ok_(response.headers['Content-Type'])
	eq_(response.headers['Content-Type'], 'application/x-sh')


def test_ddwrt_download_return_correct_header():
	response = app.head('{}/ddwrt/download'.format(base_url))
	ok_(response.status_code == OK)
	ok_(response.headers['Content-Type'])
	eq_(response.headers['Content-Type'], 'application/gzip')
