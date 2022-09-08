# -*- coding: utf-8 -*-

from __future__ import print_function

import os
import json
import inspect
import time
import requests

from datetime import datetime, timedelta

try:
	from httplib import (
		UNAUTHORIZED,
		BAD_REQUEST,
		NOT_FOUND,
		OK,
		FORBIDDEN,
		NO_CONTENT,
		CREATED
	)
except ImportError:
	from http.client import (
		UNAUTHORIZED,
		BAD_REQUEST,
		NOT_FOUND,
		OK,
		FORBIDDEN,
		NO_CONTENT,
		CREATED
	)

from utils import *
from config import *


PAYPAL_AUTH_HDR = None

@retry(Exception, cdata='method={}'.format(inspect.stack()[0][3]))
def get_paypal_auth_hdr():
	headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Accept-Language': 'en_US'
	}

	param = {'grant_type': 'client_credentials'}
	url = '{}/oauth2/token'.format(PAYPAL_BASE_URL)

	res = requests.post(
		url,
		auth=(PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET),
		headers=headers,
		data=param,
		timeout=DEFAULT_TIMEOUT
	)

	if DEBUG: print('{}: {}, {}'.format(
		inspect.stack()[0][3],
		res.status_code,
		res.content
	))
	payload = json.loads(res.text)
	auth_hdr = '{} {}'.format(payload['token_type'], payload['access_token'])

	return auth_hdr


@retry(Exception, cdata='method={}'.format(inspect.stack()[0][3]))
def get_pp_billing(bid=None, btype='agreements', status='ACTIVE'):
	global PAYPAL_AUTH_HDR

	if btype in ['agreements'] and not bid: abort(BAD_REQUEST)

	headers = {
		'Authorization': PAYPAL_AUTH_HDR,
		'Content-Type': 'application/json'
	}

	if bid:
		url = '{}/payments/billing-{}/{}'.format(PAYPAL_BASE_URL, btype, bid)
	else:
		url = '{}/payments/billing-{}?status={}'.format(
			PAYPAL_BASE_URL,
			btype,
			status.lower()
		)

	res = requests.get(url, headers=headers)
	if DEBUG: print('{}: {}, {}'.format(
		inspect.stack()[0][3],
		res.status_code,
		res.content
	))

	if res.status_code in [UNAUTHORIZED, FORBIDDEN]:
		PAYPAL_AUTH_HDR = get_paypal_auth_hdr()

	return res


@retry(Exception, cdata='method={}'.format(inspect.stack()[0][3]))
def create_pp_billing_plan(bptype='trial'):
	global PAYPAL_AUTH_HDR

	headers = {
		'Authorization': PAYPAL_AUTH_HDR,
		'Content-Type': 'application/json'
	}

	trial_payment_def = {
		'name': 'black.box one month free trial payment definition',
		'type': 'TRIAL',
		'frequency': 'MONTH',
		'frequency_interval': 1,
		'amount': {
			'value': 0,
			'currency': DEFAULT_CURRENCY
		},
		'cycles': 1,
		'charge_models': [
			{
				'type': 'SHIPPING',
				'amount': {
					'value': 0,
					'currency': DEFAULT_CURRENCY
				}
			},
			{
				'type': 'TAX',
				'amount': {
					'value': 0,
					'currency': DEFAULT_CURRENCY
				}
			}
		]
	}

	body = {
		'name': 'blackbox',
		'description': 'black.box subscription billing plan ({})'.format(bptype),
		'type': 'INFINITE',
		'payment_definitions': [
			{
				'name': 'black.box monthly subscription payment definition',
				'type': 'REGULAR',
				'frequency': 'MONTH',
				'frequency_interval': 1,
				'amount': {
					'value': DEFAULT_MONTHLY_AMOUNT,
					'currency': DEFAULT_CURRENCY
				},
				'cycles': 0,
				'charge_models': [
					{
						'type': 'SHIPPING',
						'amount': {
							'value': 0,
							'currency': DEFAULT_CURRENCY
						}
					},
					{
						'type': 'TAX',
						'amount': {
							'value': 0,
							'currency': DEFAULT_CURRENCY
						}
					}
				]
			}
		],
		'merchant_preferences': {
			'setup_fee': {
				'value': 0,
				'currency': DEFAULT_CURRENCY
			},
			'return_url': PAYPAL_RETURN_URL,
			'cancel_url': PAYPAL_CANCEL_URL,
			'auto_bill_amount': 'YES',
			'initial_fail_amount_action': 'CONTINUE',
			'max_fail_attempts': 2
		}
	}

	if bptype == 'trial':
		body['payment_definitions'].insert(0, trial_payment_def)

	data = json.dumps(body)
	url = '{}/payments/billing-plans'.format(PAYPAL_BASE_URL)
	res = requests.post(url, headers=headers, data=data)
	if DEBUG: print('{}: {}, {}'.format(
		inspect.stack()[0][3],
		res.status_code,
		res.content
	))

	if res.status_code in [UNAUTHORIZED, FORBIDDEN]:
		PAYPAL_AUTH_HDR = get_paypal_auth_hdr()

	if res.status_code not in [OK, CREATED, NO_CONTENT]:
		raise AssertionError((res.status_code, res.content))

	return res


@retry(Exception, cdata='method={}'.format(inspect.stack()[0][3]))
def update_pp_billing_plan(id=None, body={}):
	global PAYPAL_AUTH_HDR

	headers = {
		'Authorization': PAYPAL_AUTH_HDR,
		'Content-Type': 'application/json'
	}

	data = json.dumps(body)
	url = '{}/payments/billing-plans/{}'.format(PAYPAL_BASE_URL, id)
	res = requests.patch(url, headers=headers, data=data)
	if DEBUG: print('{}: {}, {}'.format(
		inspect.stack()[0][3],
		res.status_code,
		res.content
	))

	if res.status_code in [UNAUTHORIZED, FORBIDDEN]:
		PAYPAL_AUTH_HDR = get_paypal_auth_hdr()

	if res.status_code not in [OK, NO_CONTENT]:
		raise AssertionError((res.status_code, res.content))

	return res


@retry(Exception, cdata='method={}'.format(inspect.stack()[0][3]))
def update_pp_billing_plan_status(id=None, status='ACTIVE'):
	global PAYPAL_AUTH_HDR

	headers = {
		'Authorization': PAYPAL_AUTH_HDR,
		'Content-Type': 'application/json'
	}

	body = [{
		'path': '/',
		'value': {
			'state': status
		},
		'op': 'replace'
	}]

	data = json.dumps(body)
	url = '{}/payments/billing-plans/{}'.format(PAYPAL_BASE_URL, id)
	res = requests.patch(url, headers=headers, data=data)
	if DEBUG: print('{}: {}, {}'.format(
		inspect.stack()[0][3],
		res.status_code,
		res.content
	))

	if res.status_code in [UNAUTHORIZED, FORBIDDEN]:
		PAYPAL_AUTH_HDR = get_paypal_auth_hdr()

	if res.status_code not in [OK, NO_CONTENT]:
		raise AssertionError((res.status_code, res.content))

	return res


@retry(Exception, cdata='method={}'.format(inspect.stack()[0][3]))
def create_pp_billing_agreement(payload=None, bptype='trial'):
	global PAYPAL_AUTH_HDR

	headers = {
		'Authorization': PAYPAL_AUTH_HDR,
		'Content-Type': 'application/json'
	}

	billing_plan = PAYPAL_BILLING_PLAN_REGULAR
	if bptype.lower() == 'trial': billing_plan = PAYPAL_BILLING_PLAN_TRIAL

	start_date = (datetime.utcnow() + timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
	body = {
		'name': 'black.box monthly subscription ({})'.format(bptype),
		'description': payload,
		'start_date': start_date,
		'plan': {
			'id': billing_plan
		},
		'payer': {
			'payment_method': 'paypal'
		}
	}

	data = json.dumps(body)
	url = '{}/payments/billing-agreements'.format(PAYPAL_BASE_URL)
	res = requests.post(url, headers=headers, data=data)
	if DEBUG: print('{}: {}, {}'.format(
		inspect.stack()[0][3],
		res.status_code,
		res.content
	))

	if res.status_code in [UNAUTHORIZED, FORBIDDEN]:
		PAYPAL_AUTH_HDR = get_paypal_auth_hdr()

	if res.status_code not in [OK, CREATED, NO_CONTENT]:
		raise AssertionError((res.status_code, res.content))

	return res


@retry(Exception, cdata='method={}'.format(inspect.stack()[0][3]))
def cancel_pp_billing_agreement(id=None):
	global PAYPAL_AUTH_HDR

	headers = {
		'Authorization': PAYPAL_AUTH_HDR,
		'Content-Type': 'application/json'
	}

	body = {
		'note': 'black.box subscription cancelled at {}'.format(
			datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
		)
	}

	data = json.dumps(body)
	url = '{}/payments/billing-agreements/{}/cancel'.format(PAYPAL_BASE_URL, id)
	res = requests.post(url, headers=headers, data=data)
	if DEBUG: print('{}: {}, {}'.format(
		inspect.stack()[0][3],
		res.status_code,
		res.content
	))

	if res.status_code in [UNAUTHORIZED, FORBIDDEN]:
		PAYPAL_AUTH_HDR = get_paypal_auth_hdr()

	if res.status_code not in [OK, CREATED, NO_CONTENT]:
		raise AssertionError((res.status_code, res.content))

	return res


@retry(Exception, cdata='method={}'.format(inspect.stack()[0][3]))
def execute_pp_billing_agreement(token=None):
	global PAYPAL_AUTH_HDR

	headers = {
		'Authorization': PAYPAL_AUTH_HDR,
		'Content-Type': 'application/json'
	}

	url = '{}/payments/billing-agreements/{}/agreement-execute'.format(
		PAYPAL_BASE_URL,
		token
	)

	res = requests.post(url, headers=headers)
	if DEBUG: print('{}: {}, {}'.format(
		inspect.stack()[0][3],
		res.status_code,
		res.content
	))

	if res.status_code in [UNAUTHORIZED, FORBIDDEN]:
		PAYPAL_AUTH_HDR = get_paypal_auth_hdr()

	if res.status_code not in [OK, CREATED, NO_CONTENT]:
		raise AssertionError((res.status_code, res.content))

	return res


if not os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
	if PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET:
		try:
			PAYPAL_AUTH_HDR = get_paypal_auth_hdr()
			if DEBUG: print('pp_auth_header={}'.format(PAYPAL_AUTH_HDR))
		except Exception as e:
			pass
