import json

from nose.tools import ok_, eq_

try:
	from httplib import OK
except:
	from http.client import OK

from hashlib import md5

from application import application
from config import *


base_url = '/api/v{}'.format(API_VERSION)
application.testing = True
app = application.test_client()


class Endpoints(object):
	def __init__(self, url):
		self.url = url


class ProviderGroup(object):
	def __init__(self, name, provider):
		self.name = name
		self.provider = provider


class LocationGroup(object):
	def __init__(self, provider, name):
		self.provider = provider
		self.name = name


class ClientCerts(object):
	def __init__(self, provider, status):
		self.provider = provider
		self.status = status


class Locations(object):
	def __init__(self, provider, group, name):
		self.provider = provider
		self.group = group
		self.name = name


class Profiles(object):
	def __init__(self, provider, group, name, md5):
		self.provider = provider
		self.group = group
		self.name = name
		self.md5 = md5


def test_status_endpoint():
	response = app.get('{}/ping'.format(base_url))
	ok_(response.status_code == OK)
	eq_(json.loads(response.data), {'ping': 'pong'})


def test_for_presense_of_cors_headers():
	def check_for_cors_headers(endpoint):
		response = app.head('{}/{}'.format(base_url, endpoint.url))
		ok_(response.status_code == OK)
		ok_(response.headers['Access-Control-Allow-Origin'])
		eq_(response.headers['Access-Control-Allow-Origin'], '*')
		ok_(response.headers['Access-Control-Allow-Headers'])
		eq_(response.headers['Access-Control-Allow-Headers'], 'origin, content-type, accept')

	for endpoint in [
		Endpoints('vpnprovider/groups'),
		Endpoints('vpnproviders'),
		Endpoints('vpnproviders/group/default'),
		Endpoints('vpnprovider/blackbox/groups'),
		Endpoints('vpnprovider/blackbox/usercert'),
		Endpoints('vpnprovider/blackbox/group/default/locations'),
		Endpoints('vpnprovider/blackbox/group/default/name/GB - United Kingdom (UDP)/profile')

	]: yield check_for_cors_headers, endpoint


def test_provider_metadata_returns_default_group():
	response = app.get('{}/vpnprovider/groups'.format(base_url))
	ok_(response.status_code == OK)
	ok_('default' in json.loads(response.data))


def test_vpn_providers_returns_blackbox_provider():
	response = app.get('{}/vpnproviders'.format(base_url))
	ok_(response.status_code == OK)
	assert 'blackbox' in json.loads(response.data)


def test_provider_groups_contain_expected_providers():
	def check_for_provider_in_group(group):
		response = app.get('{}/vpnproviders/group/{}'.format(base_url, group.name))
		ok_(response.status_code == OK)
		assert group.provider in json.loads(response.data)

	for group in [ProviderGroup('default', 'blackbox')]:
		yield check_for_provider_in_group, group


def test_providers_contain_expected_location_group_or_groups():
	def check_for_location_group_in_provider(group):
		response = app.get('{}/vpnprovider/{}/groups'.format(base_url, group.provider))
		ok_(response.status_code == OK)
		assert group.name in json.loads(response.data)

	for group in [
		LocationGroup('blackbox', 'default'),
		LocationGroup('AirVPN', 'DNS Names')

	]: yield check_for_location_group_in_provider, group


def test_providers_return_expected_client_cert_flag():
	def check_for_client_cert_flag(cert):
		response = app.get('{}/vpnprovider/{}/usercert'.format(
			base_url,
			cert.provider
		))
		ok_(response.status_code == OK)
		eq_(json.loads(response.data), cert.status)

	for cert in [
		ClientCerts('blackbox', False),
		ClientCerts('ExpressVPN', False),
		ClientCerts('CyberGhost', True)
	]: yield check_for_client_cert_flag, cert


def test_providers_return_expected_locations():
	def check_for_locations_in_provider(location):
		response = app.get('{}/vpnprovider/{}/group/{}/locations'.format(
			base_url,
			location.provider,
			location.group
		))
		ok_(response.status_code == OK)
		ok_([loc for loc in json.loads(response.data) if loc['name'] == location.name])

	for location in [
		Locations(
			'blackbox',
			'default',
			'US - United States (UDP)'
		),
		Locations(
			'AirVPN',
			'IP Addresses',
			'United-States (UDP)')

		]: yield check_for_locations_in_provider, location


def test_providers_return_valid_vpn_profile():
	def check_for_vpn_profile(profile):
		response = app.get(
			'{}/vpnprovider/{}/group/{}/name/{}/profile'.format(
				base_url,
				profile.provider,
				profile.group,
				profile.name
		))
		ok_(response.status_code == OK)
		m = md5()
		m.update(response.data)
		digest = m.hexdigest()
		eq_(profile.md5, digest)

	for profile in [
		Profiles(
			'blackbox',
			'default',
			'US - United States (UDP)',
			'b63aaca14838495aa881feb116ac8487'
		),
		Profiles(
			'ExpressVPN',
			'default',
			'Vietnam (UDP)',
			'2afca0ed839d6bc4dfdd3a336e94ccb0'
		)

	]: yield check_for_vpn_profile, profile
