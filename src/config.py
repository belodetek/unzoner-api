# -*- coding: utf-8 -*-
import os


# application defaults
COUNTRY_FLAGS_SIZE = os.getenv('COUNTRY_FLAGS_SIZE', 'png100px')
COUNTRY_FLAGS_DIR = os.getenv('COUNTRY_FLAGS_DIR', 'country-flags')

COUNTRY_FLAGS_REPO = os.getenv(
	'COUNTRY_FLAGS_REPO',
	'https://github.com/hjnilsson/country-flags.git'
)

COUNTRY_FLAGS_TAG = os.getenv(
	'COUNTRY_FLAGS_TAG',
	'png100px'
)

TARGET_COUNTRY = os.getenv('TARGET_COUNTRY', 'United States')
GEOIP_URL = os.getenv('GEOIP_URL', 'http://api.ipstack.com')
GEOIP_API_KEY = os.getenv('GEOIP_API_KEY', None)
MAX_LAST_SEEN_DAYS = int(os.getenv('MAX_LAST_SEEN_DAYS', 365))
PURGE = bool(int(os.getenv('PURGE', False)))
RESIN_APP_ID = os.getenv('RESIN_APP_ID')
SMTP_FROM = os.getenv('SMTP_FROM', None)
SMTP_RCPT_TO = os.getenv('SMTP_RCPT_TO', None)
SMTP_HOST = os.getenv('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = os.getenv('SMTP_PORT', 465)
SMTP_USERNAME = os.getenv('SMTP_USERNAME', None)
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', None)
LISTEN_ADDR = os.getenv('LISTEN_ADDR', '0.0.0.0')
PORT = int(os.getenv('PORT', 5000))
THREADED = bool(int(os.getenv('THREADED', False)))
DEBUG = bool(int(os.getenv('DEBUG', False)))
DEBUGGER = bool(int(os.getenv('DEBUGGER', False)))
LOCAL_DEVICE = os.getenv('LOCAL_DEVICE', 'unzoner.com')
DEFAULT_TRIES = int(os.getenv('DEFAULT_TRIES', 3))
DEFAULT_DELAY = int(os.getenv('DEFAULT_DELAY', 2))
DEFAULT_BACKOFF = int(os.getenv('DEFAULT_BACKOFF', 2))
DEFAULT_TIMEOUT = int(os.getenv('DEFAULT_TIMEOUT', 5))
DEVICE_TYPES = [int(dt) for dt in os.getenv('DEVICE_TYPES', '0 1 2 3 4 5').split()]
DEVICE_TYPE = os.getenv('DEVICE_TYPE', '2')
PROTO_TYPES = [int(pt) for pt in os.getenv('PROTO_TYPES', '4 6').split()]
VPN_PROFILES = os.getenv('VPN_PROFILES', 'vpnprofiles')
GITHUB_USERNAME = os.getenv('GITHUB_USERNAME', 'ab77')
GITHUB_USER = os.getenv('GITHUB_USER', 'ab77')
GITHUB_ACCESS_TOKEN = os.getenv('GITHUB_ACCESS_TOKEN', None)
DDWRT_APP = os.getenv('DDWRT_APP', 'unzoner-mypage')
DDWRT_GIT_URL = os.getenv(
	'DDWRT_GIT_URL',
	'https://{}:{}@github.com/{}/ddwrt-mypage.git'.format(
		GITHUB_USERNAME,
		GITHUB_ACCESS_TOKEN,
		GITHUB_USER
	)
)

DDWRT_GIT_DIR = os.getenv('DDWRT_GIT_DIR', 'ddwrt-mypage')
DDWRT_GIT_TAG = os.getenv('DDWRT_GIT_TAG', 'master')

BOOTSTRAP_CSS = os.getenv(
	'BOOTSTRAP_CSS',
	'user/css/bootstrap.min.css'
) # for available themes, visit: https://bootswatch.com/

LOGO = os.getenv('LOGO', 'user/img/logo.png')
API_HOST = os.getenv('API_HOST', 'https://api-dev.belodedenko.me')
API_SECRET = os.getenv('API_SECRET', None)
API_VERSION = os.getenv('API_VERSION', '1.0')
RESN_API_HOST = os.getenv('RESN_API_HOST', 'https://api.balena-cloud.com')
RESN_USERNAME = os.getenv('RESN_USERNAME', 'anton@balena.io')
RESN_PASSWORD = os.getenv('RESN_PASSWORD', None)
STALE_NODE_THSHLD = int(os.getenv('STALE_NODE_THSHLD', 300)) # seconds
RDS_HOSTNAME = os.getenv('RDS_HOSTNAME', None)
RDS_PORT = int(os.getenv('RDS_PORT', 3306))
RDS_DB_NAME = os.getenv('RDS_DB_NAME', 'ebdb')
RDS_USER = os.getenv('RDS_USER', 'admin')
RDS_PASSWORD = os.getenv('RDS_PASSWORD', None)
RDS_URL = '{}:{}'.format(RDS_HOSTNAME, RDS_PORT)

SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://{}:{}@{}/{}'.format(
	RDS_USER,
	RDS_PASSWORD,
	RDS_URL,
	RDS_DB_NAME
)

SQLALCHEMY_POOL_RECYCLE = int(os.getenv('SQLALCHEMY_POOL_RECYCLE', 3600))

SQLALCHEMY_TRACK_MODIFICATIONS = bool(
	int(os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS', False))
)

CACHE_HOST = os.getenv('CACHE_HOST', None)
CACHE_PORT = int(os.getenv('CACHE_PORT', 6379))
DEFAULT_CACHE_TTL = int(os.getenv('DEFAULT_CACHE_TTL', 300)) # seconds
PAYPAL_BASE_URL = os.getenv('PAYPAL_BASE_URL', None)
PAYPAL_CLIENT_ID = os.getenv('PAYPAL_CLIENT_ID', None)
PAYPAL_CLIENT_SECRET = os.getenv('PAYPAL_CLIENT_SECRET', None)
PAYPAL_BILLING_PLAN_TRIAL = os.getenv('PAYPAL_BILLING_PLAN_TRIAL', None)
PAYPAL_BILLING_PLAN_REGULAR = os.getenv('PAYPAL_BILLING_PLAN_REGULAR', None)

PAYPAL_RETURN_URL = '{}/api/v{}/paypal/billing-agreements/execute'.format(
	API_HOST,
	API_VERSION
)

PAYPAL_CANCEL_URL = '{}/api/v{}/paypal/billing-agreements/cancel'.format(
	API_HOST,
	API_VERSION
)

PAYPAL_VERIFY_WEBHOOK = bool(int(os.getenv('PAYPAL_VERIFY_WEBHOOK', True)))
PAYPAL_WEBHOOK_ID = os.getenv('PAYPAL_WEBHOOK_ID', None)
DEFAULT_CURRENCY = os.getenv('DEFAULT_CURRENCY', 'EUR')
DEFAULT_MONTHLY_AMOUNT = float(os.getenv('DEFAULT_MONTHLY_AMOUNT', 9.95))
BLACKBOX_RETURN_URL = os.getenv('BLACKBOX_RETURN_URL', 'https://dash-dev.belodedenko.me')
BLOCKCYPHER_API_TOKEN = os.getenv('BLOCKCYPHER_API_TOKEN', None)
BLOCKCYPHER_WEBHOOK_TOKEN = os.getenv('BLOCKCYPHER_WEBHOOK_TOKEN', None)
BLOCKCYPHER_WALLET_NAME = os.getenv('BLOCKCYPHER_WALLET_NAME', 'blackbox-payments-testnet')
BLOCKCYPHER_COIN_SYMBOL = os.getenv('BLOCKCYPHER_COIN_SYMBOL', 'btc-testnet')
BITCOIN_PAYMENT_WALLET_XPUBKEY = os.getenv('BITCOIN_PAYMENT_WALLET_XPUBKEY', None)
BITCOIN_SATOSHI = int(os.getenv('BITCOIN_SATOSHI', 100000000))
BITCOIN_CONFIRMATION_EVENT = os.getenv('BITCOIN_CONFIRMATION_EVENT','unconfirmed-tx')
BITCOIN_MAX_CONFIRMATIONS = int(os.getenv('BITCOIN_MAX_CONFIRMATIONS', 0))

# https://raw.githubusercontent.com/lukes/ISO-3166-Countries-with-Regional-Codes/master/all/all.json
COUNTRY_DATA = os.getenv('COUNTRY_DATA', 'alpha.json')
BLACKBOX_DATA = os.getenv('BLACKBOX_DATA', 'blackbox.json')

PURGE_WHITELIST = os.getenv(
	'PURGE_WHITELIST',
	'b55b561ea8fcc9b11105f05f1e8b5095'
) # demo

VPN_PROVIDERS_GIT_DIR = os.getenv('VPN_PROVIDERS_GIT_DIR', VPN_PROFILES)
VPN_PROVIDERS_GIT_TAG = os.getenv('VPN_PROVIDERS_GIT_TAG', 'master')
VPN_PROVIDERS_GIT_USER = os.getenv('VPN_PROVIDERS_GIT_USER', GITHUB_USER)
VPN_PROVIDERS_GIT_URL = os.getenv(
	'VPN_PROVIDERS_GIT_URL',
	'https://{}:{}@github.com/{}/service.vpn.manager.providers.git'.format(
		GITHUB_USERNAME,
		GITHUB_ACCESS_TOKEN,
		VPN_PROVIDERS_GIT_USER
	)
)
