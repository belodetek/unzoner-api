import json
import jwt
import socket
import struct

from nose.tools import ok_, eq_, assert_is_not_none

try:
	from mock import Mock, patch
except ImportError:
	from unittest.mock import Mock, patch

try:
	from httplib import OK, FOUND, CREATED
except:
	from http.client import OK, FOUND, CREATED

from uuid import uuid4
from datetime import datetime, timedelta

from config import *
from application import application
from utils import generate_hash_key


base_url = '/api/v{}'.format(API_VERSION)
headers = {
	'X-Auth-Token': API_SECRET,
	'Content-Type': 'application/json'
}

application.testing = True
app = application.test_client()


class PayPalTestClass():
	default_description = 'eyJpIjoiNGQ1ZWRlZTU0MTMzOTE0ZWJlOWM0YzVmZGQ3NTE1ODQiLCJwIjoiSXpSSEZQaW1nMUFzQ0FOZyIsInQiOiJERFdSVCIsInUiOiIzMjMyMjM4MzM3In0'
	default_baid = 'I-KU481EPUNLLW'
	default_state = 'Active'
	default_token = 'EC-7RG27775K0444514X'


	@property
	def billing_plans(self):
		return {
			'links': [
				{
					'href': 'https://api.sandbox.paypal.com/v1/payments/billing-plans?page_size=10&page=0&start=1&status=active',
					'method': 'GET',
					'rel': 'start'
					},
				{
					'href': 'https://api.sandbox.paypal.com/v1/payments/billing-plans?page_size=10&page=0&status=active',
					'method': 'GET',
					'rel': 'last'
				 }
				],
			'plans': [
				{
					'create_time': '2016-10-05T14:29:58.510Z',
					'description': 'black.box subscription billing plan',
					'id': 'P-0W441298CC481532LSVAEA3Q',
					'links':
					[
						{
							'href': 'https://api.sandbox.paypal.com/v1/payments/billing-plans/P-0W441298CC481532LSVAEA3Q',
							'method': 'GET',
							'rel': 'self'
							}
						],
					'name': 'blackbox',
					'state': 'ACTIVE',
					'type': 'INFINITE',
					'update_time': '2016-10-05T14:34:59.911Z'
					},
				{
					'create_time': '2016-12-26T14:13:53.689Z',
					'description': 'black.box subscription billing plan',
					'id': 'P-5ML31898ML210453DHN5P7GI',
					'links':
					[
						{
							'href': 'https://api.sandbox.paypal.com/v1/payments/billing-plans/P-5ML31898ML210453DHN5P7GI',
							'method': 'GET',
							'rel': 'self'
							}
						],
					'name': 'blackbox',
					'state': 'ACTIVE',
					'type': 'INFINITE',
					'update_time': '2016-12-26T14:17:08.008Z'
					}
				]
			}


	@property
	def billing_agreement(self):
		return {
			'agreement_details': {
				'cycles_completed': '2',
				'cycles_remaining': '18446744073709551614',
				'failed_payment_count': '0',
				'final_payment_date': '1970-01-01T00:00:00Z',
				'last_payment_amount': {
					'currency': 'EUR',
					'value': '9.95'
					},
				'last_payment_date': '2017-07-23T10:44:55Z',
				'next_billing_date': '2017-08-23T10:00:00Z',
				'outstanding_balance': {
					'currency': 'EUR',
					'value': '0.00'
					}
				},
			'links': [
				{
					'href': 'https://api.sandbox.paypal.com/v1/payments/billing-agreements/I-KU481EPUNLLW/suspend',
					'method': 'POST',
					'rel': 'suspend'
				},
				{
					'href': 'https://api.sandbox.paypal.com/v1/payments/billing-agreements/I-KU481EPUNLLW/re-activate',
					'method': 'POST',
					'rel': 're_activate'
				},
				{
					'href': 'https://api.sandbox.paypal.com/v1/payments/billing-agreements/I-KU481EPUNLLW/cancel',
					'method': 'POST',
					'rel': 'cancel'
				},
				{
					'href': 'https://api.sandbox.paypal.com/v1/payments/billing-agreements/I-KU481EPUNLLW/bill-balance',
					'method': 'POST',
					'rel': 'self'
				},
				{
					'href': 'https://api.sandbox.paypal.com/v1/payments/billing-agreements/I-KU481EPUNLLW/set-balance',
					'method': 'POST',
					'rel': 'self'
					}
				],
			'payer': {
				'payer_info': {
					'email': 'blackbox-preview@belodedenko.me',
					'first_name': 'Blackbox',
					'last_name': 'Preview',
					'payer_id': '96729WUHRDKEW',
					'shipping_address': {
						'city': 'Wolverhampton',
						'line1': '1 Main Terrace',
						'postal_code': 'W12 4LQ',
						'recipient_name': 'Blackbox Preview',
						'state': 'West Midlands'
						}
					},
				'payment_method': 'paypal',
				'status': 'verified'
				},
			'plan': {
				'merchant_preferences': {
					'auto_bill_amount': 'YES',
					'max_fail_attempts': '0',
					'setup_fee': {
						'currency': 'EUR',
						'value': '0.00'
						}
					},
				'payment_definitions': [
					{
						'amount': {
							'currency': 'EUR',
							'value': '9.95'
							},
						'charge_models': [
							{
								'amount': {
									'currency': 'EUR',
									'value': '0.00'
									},
								'type': 'TAX'
								},
							{
								'amount': {
									'currency': 'EUR',
									'value': '0.00'
									},
								'type': 'SHIPPING'
								}
							],
						'cycles': '0',
						'frequency': 'Month',
						'frequency_interval': '1',
						'type': 'REGULAR'
						}
					]
				},
			'shipping_address': {
				'city': 'Wolverhampton',
				'country_code': 'GB',
				'line1': '1 Main Terrace',
				'postal_code': 'W12 4LQ',
				'recipient_name': 'Blackbox Preview',
				'state': 'West Midlands'
				},
			'start_date': '2017-06-23T07:00:00Z'
			}


	@property
	def create_billing_agreement(self):
			return {
			'name': 'black.box monthly subscription (trial)',
			'plan': {
				'id': 'P-0W441298CC481532LSVAEA3Q',
				'state': 'ACTIVE',
				'name': 'blackbox',
				'description': 'black.box subscription billing plan',
				'type': 'INFINITE',
				'payment_definitions': [
					{
						'id': 'PD-9513234488401030FSVAEA3Q',
						'name': 'black.box one month free trial payment definition',
						'type': 'TRIAL',
						'frequency': 'Month',
						'amount': {
							'currency': 'EUR',
							'value': '0'
							},
						'cycles': '1',
						'charge_models': [
							{
								'id': 'CHM-08F135248W970842XSVAEA3Y',
								'type': 'TAX',
								'amount': {
									'currency': 'EUR',
									'value': '0'
									}
								},
							{
								'id': 'CHM-0E934493G85630539SVAEA3Q',
								'type': 'SHIPPING',
								'amount': {
									'currency': 'EUR',
									'value': '0'
									}
								}
							],
						'frequency_interval': '1'
					},
					{
						'id': 'PD-8WY64123N8538225USVAEA3Y',
						'name': 'black.box monthly subscription payment definition',
						'type': 'REGULAR',
						'frequency': 'Month',
						'amount': {
							'currency': 'EUR',
							'value': '9.95'
							},
						'cycles': '0',
						'charge_models': [
							{
								'id': 'CHM-988285819F8420149SVAEA3Y',
								'type': 'TAX',
								'amount': {
									'currency': 'EUR',
									'value': '0'
									}
								},
							{
								'id': 'CHM-3A155820NB617344ASVAEA3Y',
								'type': 'SHIPPING',
								'amount': {
									'currency': 'EUR',
									'value': '0'
									}
								}
							],
						'frequency_interval': '1'
						}
					],
				'merchant_preferences': {
					'setup_fee': {
						'currency': 'EUR',
						'value': '0'
					},
					'max_fail_attempts': '0',
					'return_url': 'https://api-dev.belodedenko.me/api/v1.0/paypal/billing-agreements/execute',
					'cancel_url': 'https://api-dev.belodedenko.me/api/v1.0/paypal/billing-agreements/cancel',
					'auto_bill_amount': 'YES',
					'initial_fail_amount_action': 'CONTINUE'
				}
			},
			'links': [
				{
					'href': 'https://www.sandbox.paypal.com/cgi-bin/webscr?cmd=_express-checkout&token=EC-49866669LD7326910',
					'rel': 'approval_url',
					'method': 'REDIRECT'
					},
				{
					'href': 'https://api.sandbox.paypal.com/v1/payments/billing-agreements/EC-49866669LD7326910/agreement-execute',
					'rel': 'execute',
					'method': 'POST'
					}
				],
			'start_date': '2017-08-10T14:48:55Z'
			}


	@property
	def exec_billing_agreement(self):
		return {
			'state': 'Active',
			'payer': {
				'payment_method': 'paypal',
				'status': 'verified',
				'payer_info': {
					'email': 'blackbox-preview@belodedenko.me',
					'first_name': 'Blackbox',
					'last_name': 'Preview',
					'payer_id': '96729WUHRDKEW',
					'shipping_address': {
						'recipient_name': 'Blackbox Preview',
						'line1': '1 Main Terrace',
						'city': 'Wolverhampton',
						'state': 'West Midlands',
						'postal_code': 'W12 4LQ',
						'country_code': 'GB'
						}
					}
				},
			'plan': {
				'payment_definitions': [
					{
						'type': 'REGULAR',
						'frequency': 'Month',
						'amount': {
							'value': '9.95'
							},
						'cycles': '0',
						'charge_models': [
							{
								'type': 'TAX',
								'amount': {
									'value': '0.00'
									}
								},
							{
								'type': 'SHIPPING',
								'amount': {
									'value': '0.00'
									}
								}
							],
						'frequency_interval': '1'
						}
					],
				'merchant_preferences': {
					'setup_fee': {
						'value': '0.00'
						},
					'max_fail_attempts': '0',
					'auto_bill_amount': 'YES'
					},
				'links': [],
				'currency_code': 'EUR'
				},
			'links': [
				{
					'href': 'https://api.sandbox.paypal.com/v1/payments/billing-agreements/I-BH0PA23DYLYM',
					'rel': 'self',
					'method': 'GET'
					}
				],
			'start_date': '2017-08-10T07:00:00Z',
			'shipping_address': {
				'recipient_name': 'Blackbox Preview',
				'line1': '1 Main Terrace',
				'city': 'Wolverhampton',
				'state': 'West Midlands',
				'postal_code': 'W12 4LQ',
				'country_code': 'GB'
				},
			'agreement_details': {
				'outstanding_balance': {
					'value': '0.00'
					},
				'cycles_remaining': '1',
				'cycles_completed': '0',
				'next_billing_date': '2017-08-10T10:00:00Z',
				'final_payment_date': '1970-01-01T00:00:00Z',
				'failed_payment_count': '0'
				}
			}


	@property
	def trial_payment_def(self):
		return {
			'type': 'TRIAL',
			'frequency': 'Month',
			'amount': {
				'value': '0.00'
				},
			'cycles': '1',
			'charge_models': [
				{
					'type': 'TAX',
					'amount': {
						'value': '0.00'
						}
					},
				{
					'type': 'SHIPPING',
					'amount': {
						'value': '0.00'
						}
					}
				],
			'frequency_interval': '1'
			}


	def __init__(
		self,
		content=None,
		description=None,
		baid=None,
		state=None,
		status_code=None
	):
		if not baid:
			self.baid = self.default_baid
		else:
			self.baid = baid

		if not description:
			self.description = self.default_description
		else:
			self.description = description

		if not state:
			self.state = self.default_state
		else:
			self.state = state

		if not status_code:
			self.status_code = OK
		else:
			self.status_code = status_code

		if not content:
			self.content = self.billing_plans
		else:
			self.content = content

		self.mock_response = Mock()
		self.mock_response.status_code = self.status_code
		self.mock_response.content = json.dumps(self.content)


class ResinTestClass():
	default_trial_expired_uid = 'J7DWYH6DJF1FM',
	default_trial_start_date = datetime.strftime(
		datetime.now(),
		'%Y-%m-%dT%H:%M:%SZ'
	)

	@property
	def trial_expired_env(self):
		return {
			'id': 52415,
			'device': {
				'__deferred': {
					'uri': '/resin/device(632179)'
					},
				'__id': 632179
				},
			'env_var_name': 'PAYPAL_TRIAL_EXPIRED',
			'__metadata': {
				'uri': '/resin/device_environment_variable(52415)',
				'type': ''
				}
			}


	@property
	def trial_start_date_env(self):
		return {
			'id': 55466,
			'device': {
				'__deferred': {
					'uri': '/resin/device(632179)'
					},
				'__id': 632179
				},
			'env_var_name': 'PAYPAL_TRIAL_START_DATE',
			'__metadata': {
				'uri': '/resin/device_environment_variable(55466)',
				'type': ''
				}
			}


	@property
	def resin_device_envs(self):
		return {'d': []}


	def __init__(
		self,
		content=None,
		trial_start_date_env=None,
		trial_start_date=None,
		trial_expired_uid=None,
		status_code=OK
	):
		if not trial_start_date:
			self.trial_start_date = self.default_trial_start_date
		else:
			self.trial_start_date = trial_start_date

		if not trial_expired_uid:
			self.trial_expired_uid = self.default_trial_expired_uid
		else:
			self.trial_expired_uid = trial_expired_uid

		if not content:
			trial_start_date_env = self.trial_start_date_env
			trial_start_date_env['value'] = self.trial_start_date
			trial_expired_env = self.trial_expired_env
			trial_expired_env['value'] = self.trial_expired_uid
			resin_device_envs = self.resin_device_envs
			resin_device_envs['d'].append(trial_expired_env)
			resin_device_envs['d'].append(trial_start_date_env)
			self.content = resin_device_envs
		else:
			self.content = content

		self.mock_response = Mock()
		self.mock_response.status_code = status_code
		self.mock_response.content = json.dumps(self.content)


def get_jwtoken_payload(
	device_type='RESIN',
	device_id=uuid4().hex[:32],
	device_passwd=generate_hash_key()[:16],
	device_ip=''
):
	token_data = {
		'i': device_id,
		'u': device_ip,
		't': device_type,
		'p': device_passwd
	}

	return jwt.encode(
		token_data,
		token_data['p'],
		algorithm='HS256'
	).decode().split('.')[1]


def ip2long(ip):
	"""
	Convert an IP string to long
	"""
	packedIP = socket.inet_aton(ip)
	return struct.unpack("!L", packedIP)[0]


@patch('application.get_pp_billing')
def test_get_billing_returns_billing_plans(mock):
	bp = PayPalTestClass()
	mock.return_value = bp.mock_response
	response = app.get('{}/paypal/billing-plans'.format(base_url), headers=headers)
	assert_is_not_none(response)
	ok_(response.status_code)
	ok_(json.loads(response.data))
	assert 'plans' in json.loads(response.data)


@patch('application.get_pp_billing')
def test_get_billing_returns_billing_agreement(mock):
	cls = PayPalTestClass()
	content = cls.billing_agreement
	content['description'] = cls.default_description
	content['id'] = cls.default_baid
	content['state'] = cls.default_state
	ba = PayPalTestClass(content=content)
	mock.return_value = ba.mock_response
	response = app.get('{}/paypal/billing-agreements'.format(base_url), headers=headers)
	assert_is_not_none(response)
	ok_(response.status_code)
	ok_(json.loads(response.data))
	assert 'agreement_details' in json.loads(response.data)


@patch('application.get_pp_billing')
def test_confirm_active_billing_agreement_returns_agreement_state(mock):
	cls = PayPalTestClass()
	content = cls. billing_agreement
	content['description'] = cls.default_description
	content['id'] = cls.default_baid
	content['state'] = cls.default_state
	ba = PayPalTestClass(content=content)
	mock.return_value = ba.mock_response
	response = app.get('{}/paypal/billing-agreements/{}/confirm'.format(
		base_url,
		PayPalTestClass.default_baid),
		headers=headers
	)

	assert_is_not_none(response)
	ok_(response.status_code)
	ok_(json.loads(response.data))
	assert 'agreement_state' in json.loads(response.data)
	assert json.loads(response.data)['agreement_state'] == 'active'


def test_create_billing_agreement_redirects_to_paypal():

	class Test():
		def __init__(self, url, description, status_code):
			self.url = url
			self.description = description
			self.status_code = status_code


	@patch('application.create_pp_billing_agreement')
	def check_create_billing_agreement(test, mock):
		cls = PayPalTestClass()
		content = cls.create_billing_agreement
		content['description'] = test.description
		ba = PayPalTestClass(content=content, status_code=test.status_code)
		mock.return_value = ba.mock_response
		response = app.get(test.url, headers=headers)
		assert_is_not_none(response)
		eq_(response.status_code, FOUND)
		assert_is_not_none(response.location)

	for test in [
		Test(
			url='{}/paypal/billing-agreements/{}/create/{}'.format(
				base_url,
				get_jwtoken_payload(),
				'trial'
			),
			description=get_jwtoken_payload(),
			status_code=CREATED
		),
		Test(
			url='{}/paypal/billing-agreements/{}/create/{}'.format(
				base_url,
				get_jwtoken_payload(),
				'regular'
			),
			description=get_jwtoken_payload(),
			status_code=CREATED
		),
		Test(
			url='{}/paypal/billing-agreements/{}/create/{}'.format(
				base_url,
				uuid4().hex,
				'trial'
			),
			description=uuid4().hex,
			status_code=CREATED
		),
		Test(
			url='{}/paypal/billing-agreements/{}/create/{}'.format(
				base_url,
				uuid4().hex,
				'regular'
			),
			description=uuid4().hex,
			status_code=CREATED
		),
		Test(
			url='{}/paypal/billing-agreements/{}/create/{}'.format(
				base_url,
				uuid4().hex,
				'trial'
			),
			description=uuid4().hex,
			status_code=CREATED
		),
		Test(
			url='{}/paypal/billing-agreements/{}/create/{}'.format(
				base_url,
				get_jwtoken_payload(),
				'regular'
			),
			description=uuid4().hex,
			status_code=CREATED
		),
		Test(
			url='{}/paypal/billing-agreements/{}/create/{}'.format(
				base_url,
				get_jwtoken_payload(),
				'regular'
			),
			description=get_jwtoken_payload(device_type='DDWRT'),
			status_code=CREATED
		),
		Test(
			url='{}/paypal/billing-agreement/create'.format(base_url),
			description=get_jwtoken_payload(device_type='OTHER'),
			status_code=CREATED)

		]: yield check_create_billing_agreement, test


def test_execute_pp_billing_agreement_redirects_to_dashboard():
	http_OK = Mock()
	http_OK.status_code = OK
	http_OK.content = None


	class Test():
		def __init__(self, description, trial_start_date, result, trial):
			self.description = description
			self.trial_start_date = trial_start_date,
			self.result = result
			self.trial = trial


	@patch('application.execute_pp_billing_agreement')
	@patch('application.get_resin_device_envs_by')
	@patch('application.create_update_resin_device_env', return_value=True)
	@patch('application.cancel_pp_billing_agreement', return_value=http_OK)
	def check_execute_pp_billing_agreement(test, *args):
		paypal_mock = args[3]
		cls = PayPalTestClass()
		content = cls.exec_billing_agreement
		if test.trial: content['plan']['payment_definitions'].append(cls.trial_payment_def)

		content['id'] = cls.default_baid
		content['description'] = test.description
		ba = PayPalTestClass(content=content)
		paypal_mock.return_value = ba.mock_response

		resin_mock = args[2]
		cls = ResinTestClass()
		evs = cls.resin_device_envs
		ev = cls.trial_start_date_env
		ev['value'] = test.trial_start_date[0]
		evs['d'].append(ev)
		resin = ResinTestClass(content=evs)
		resin_mock.return_value = resin.mock_response

		response = app.get(
			'{}/paypal/billing-agreements/execute?token={}'.format(
				base_url,
				PayPalTestClass.default_token
			),
			headers=headers
		)

		assert_is_not_none(response)
		eq_(response.status_code, FOUND)
		assert_is_not_none(response.location)
		ok_(response.location.split('&')[1].startswith(test.result))

	month_ago = datetime.strftime(
		datetime.today() - timedelta(weeks=5),
		'%Y-%m-%dT%H:%M:%SZ'
	)

	for test in [
		Test(
			description=uuid4().hex,
			trial=True,
			trial_start_date=ResinTestClass.default_trial_start_date,
			result='result=200'
		),
		Test(
			description=uuid4().hex,
			trial=True,
			trial_start_date=month_ago,
			result='result=402'
		),
		Test(
			description=get_jwtoken_payload(),
			trial=True,
			trial_start_date=ResinTestClass.default_trial_start_date,
			result='result=200'
		),
		Test(
			description=get_jwtoken_payload(),
			trial=True,
			trial_start_date=month_ago,
			result='result=402'
		),
		Test(
			description=uuid4().hex,
			trial=False,
			trial_start_date=ResinTestClass.default_trial_start_date,
			result='result=200'
		),
		Test(
			description=uuid4().hex,
			trial=False,
			trial_start_date=month_ago,
			result='result=200'
		),
		Test(
			description=get_jwtoken_payload(),
			trial=False,
			trial_start_date=ResinTestClass.default_trial_start_date,
			result='result=200'
		),
		Test(
			description=get_jwtoken_payload(),
			trial=False,
			trial_start_date=month_ago,
			result='result=200'
		),
		Test(
			description=get_jwtoken_payload(
				device_type='DDWRT',
				device_ip=ip2long('192.168.11.1'
			)),
			trial=True,
			trial_start_date=ResinTestClass.default_trial_start_date,
			result='type=warning'
		),
		Test(
			description=get_jwtoken_payload(
				device_type='DDWRT',
				device_ip=ip2long('192.168.11.1')
			),
			trial=False,
			trial_start_date=ResinTestClass.default_trial_start_date,
			result='type=success'
		),
		Test(
			description=get_jwtoken_payload(device_type='OTHER'),
			trial=True,
			trial_start_date=ResinTestClass.default_trial_start_date,
			result='msg=Free%20trial%20period%20is%20not%20available'
		),
		Test(
			description=get_jwtoken_payload(device_type='OTHER'),
			trial=False,
			trial_start_date=ResinTestClass.default_trial_start_date,
			result='msg=Subscribed%20successfully')

		]: yield check_execute_pp_billing_agreement, test
