import datetime
import json

from nose.tools import ok_, eq_, assert_is_not_none

try:
	from mock import patch
except ImportError:
	from unittest.mock import patch

try:
	from httplib import OK
except ImportError:
	from http.client import OK

from uuid import uuid4
from sqlalchemy.orm import sessionmaker

from application import application
from config import *

base_url = '/api/v{}'.format(API_VERSION)
application.testing = True
app = application.test_client()
guid = uuid4().hex


class TestDevices():
	def __init__(self, type, guid, af):
		self.type = type
		self.guid = guid
		self.af = af


class Device():
	def __init__(self, dt, guid, bytesin, bytesout):
		self.idx = 0
		self.dt = dt
		self.guid = guid
		self.bytesin = bytesin
		self.bytesout = bytesout

	def keys(self):
		return [k for k in self.__dict__.keys() if not k == 'idx']

	def values(self):
		return (self.dt, self.guid, self.bytesin, self.bytesout)

	def __iter__(self):
		return self

	def __next__(self):
		try:
			item = self.values()[self.idx]
		except IndexError:
			raise StopIteration
		self.idx += 1
		return item

	next = __next__


def test_stats_endpoint_returns_results():

	@patch('application.session', return_value=sessionmaker())
	@patch('application.get_results_from_cursor',
		   return_value=[
			   Device(datetime.datetime(2022, 9, 7, 0, 0, 0), guid, 268936, 287532),
			   Device(datetime.datetime(2022, 9, 7, 0, 1, 0), guid, 378, 405),
			   Device(datetime.datetime(2022, 9, 7, 0, 2, 0), guid, 420, 450)
			]
	)
	def check_stats_endpoint_returns_results(device, *args):
		response = app.get('{}/device/{}/{}/{}/stats'.format(
			base_url,
			device.type,
			device.guid,
			device.af
		))

		ok_(response.status_code == OK)
		assert_is_not_none(response.data)
		assert_is_not_none([v['bytesin'] for v in json.loads(response.data)])
		assert_is_not_none([v['bytesout'] for v in json.loads(response.data)])
		assert_is_not_none([v['guid'] for v in json.loads(response.data)])
		assert_is_not_none([v['dt'] for v in json.loads(response.data)])

	for test in [
		TestDevices(2, uuid4().hex, 4),
	]: yield check_stats_endpoint_returns_results, test
