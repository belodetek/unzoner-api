import json

from nose.tools import ok_, eq_, assert_is_not_none

try:
    from mock import Mock, patch
except ImportError:
    from unittest.mock import Mock, patch

try:
    from httplib import OK
except:
    from http.client import OK

from uuid import uuid4
from time import sleep

from config import *
from application import application                                                
from utils import background_smtp_send


base_url = '/api/v{}'.format(API_VERSION)

auth_hdr = {
    'X-Auth-Token': API_SECRET
}

application.testing = True
app = application.test_client()


class Country():
    def __init__(self, name, alpha2):
        self.name = name
        self.alpha2 = alpha2


class ASN():
    def __init__(self, alpha2, service, name):
        self.alpha2 = alpha2
        self.service = service
        self.name = name


class Domains():
    def __init__(self, alpha2, service, name):
        self.alpha2 = alpha2
        self.service = service
        self.name = name


class Service():
    def __init__(self, alpha2, default, name):
        self.alpha2 = alpha2
        self.default = default
        self.name = name


@patch('utils.smtplib')
def test_background_smtp_send_returns_thread(mock):
    smtplib = Mock()
    mock.return_value = smtplib
    smtplib.smtp = None
    smtplib.ehlo = None
    smtplib.login = None
    smtplib.sendmail = None
    smtplib.quit = None          
    process = background_smtp_send(
        subject='{} payment of {} Satoshi received from {}'.format(
            'btc-testnet',
            '100000',
            uuid4().hex
        ),
        preamble='Bitcoin payment notification',
        body=json.dumps(
            {
                'webhook': {
                    'hello': 'world'
                },
                'api_response': {'hello': 'world'}
            }
        )
    )
    assert_is_not_none(process)
    eq_(process.is_alive(), True)
    while process.is_alive(): sleep(0.1) 


def test_country_endpoint_returns_correct_alpha2():
    def check_country_alpha2_by_country_name(country):
        response = app.get(
            '{}/country/{}'.format(
                base_url,
                country.name
            ),
            headers=auth_hdr
        )
        ok_(response.status_code == OK)
        eq_(country.alpha2, response.data.decode())

    for country in [
        Country('United Kingdom', 'GB'),
        Country('United States', 'US')
    ]: yield check_country_alpha2_by_country_name, country


def test_asn_endpoint_returns_correct_asns_for_service():
    def check_asns_by_service(asn):
        response = app.get(
            '{}/alpha/{}/asns/{}'.format(
                base_url,
                asn.alpha2,
                asn.service
            ),
            headers=auth_hdr
        )
        ok_(response.status_code == OK)
        eq_(asn.name, response.data.decode())

    for asn in [
        ASN('GB', 'iplayer', 'AS2818'),
        ASN('US', 'netflix', 'AS2906')
    ]: yield check_asns_by_service, asn


def test_asn_endpoint_returns_correct_domains_for_service():
    def check_domains_by_service(domain):
        response = app.get(
            '{}/alpha/{}/domains/{}'.format(
                base_url,
                domain.alpha2,
                domain.service
            ),
            headers=auth_hdr
        )
        ok_(response.status_code == OK)
        assert domain.name in (response.data.decode()).split(' ')

    for domain in [
        ASN('GB', 'iplayer', 'bbc.co.uk'),
        ASN('US', 'netflix', 'netflix.com')
    ]: yield check_domains_by_service, domain


def test_service_endpoint_returns_correct_services():
    def check_available_services_by_alpha2(service):
        response = app.get(
            '{}/alpha/{}/services/default/{}'.format(
                base_url,
                service.alpha2,
                service.default
            ),
            headers=auth_hdr
        )
        ok_(response.status_code == OK)        
        assert service.name in (response.data.decode()).split(' ')

    for service in [
        Service('GB', '1', 'common'),
        Service('US', '1', 'common'),
        Service('US', '0', 'netflix'),
        Service('GB', '0', 'iplayer')
    ]: yield check_available_services_by_alpha2, service
