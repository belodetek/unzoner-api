# unzoner-api
> [black.box Unzoner](https://www.unzoner.com/#technical-architecture) API service using Flask on Python

This block implements black.box Unzoner API backend, which provides a common interface
for all other services.


## usage
* add the latest [unzoner-api](https://hub.balena.io/organizations/belodetek/blocks) block to your balenaCloud fleet composition (e.g. `amd64`)

```yml
version: '2.4'

services:
  unzoner-api:
    # https://www.balena.io/docs/learn/develop/blocks/#using-your-block-in-other-projects
    image: bh.cr/belodetek/unzoner-api-amd64
    restart: unless-stopped
    ports:
      # it is assumed there is a load-baancer/proxy fronting the API
      - "80:80/tcp"
    # https://www.balena.io/docs/reference/supervisor/docker-compose/#labels
    labels:
      io.balena.update.strategy: download-then-kill

  unzoner-dns:
    ...
```

## configuration
> set fleet environment variables

name | description | example
--- | --- | ---
API_HOST | your Unzoner API URL | (e.g.) `https://api.acme.com`
API_SECRET | shared secret | (e.g.) `openssl rand -hex 16`
API_VERSION | your Unzoner API version | (e.g.) `1.0`
BITCOIN_PAYMENT_WALLET_XPUBKEY | public key of the wallet for incoming payments | `xpub` format
BLOCKCYPHER_API_TOKEN | API token | [link](https://www.blockcypher.com/getting-started.html)
BLOCKCYPHER_COIN_SYMBOL | Bitcoin channel | `btc`, `btc-testnet`
BLOCKCYPHER_WALLET_NAME | name of the wallet for incoming payments | [link](https://www.blockcypher.com/getting-started.html)
BLOCKCYPHER_WEBHOOK_TOKEN | WebHook API token | [link](https://www.blockcypher.com/getting-started.html)
GEOIP_API_KEY | API key | [link](http://ipstack.com)
GITHUB_ACCESS_TOKEN | GitHub PAT with access to private repositories | [link](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token)
PAYPAL_BASE_URL | PayPal API | [link](https://api.paypal.com/v1)
PAYPAL_BILLING_PLAN_REGULAR | PayPal regular billing plan ID | see, [create_pp_billing_plan](src/paypal.py)
PAYPAL_BILLING_PLAN_TRIAL | PayPal trial billing plan ID | see, [create_pp_billing_plan](src/paypal.py)
PAYPAL_CLIENT_ID | PayPal client ID | [link](https://developer.paypal.com/)
PAYPAL_CLIENT_SECRET | PayPal secret | [link](https://developer.paypal.com/)
PAYPAL_WEBHOOK_ID | PayPal WebHook ID | [link](https://developer.paypal.com/)
RESIN_APP_ID | balena fleet IDs | comma separated list of fleet IDs
RESN_PASSWORD | balenaCloud password | [link](https://www.balena.io/cloud/) 
RESN_USERNAME | balenaCloud username | [link](https://www.balena.io/cloud/)
SMTP_FROM | Your Gmail email address | (e.g) `team@acme.com`
SMTP_PASSWORD | Google app password | [link](https://support.google.com/accounts/answer/185833?hl=en)
SMTP_RCPT_TO | Your Gmail email address | (e.g) `team@acme.com`
SMTP_USERNAME | Your Gmail email address | (e.g) `team@acme.com`


## API reference
> include convenience function to escape unsafe characters in URLs

    api_url="${API_HOST}/api/v${API_VERSION}"

    curl "${api_url}/ping"

    function urlencode() {
        local encoded="$1"
        encoded=$(echo ${encoded} | sed 's/%/%25/g')
        encoded=$(echo ${encoded} | sed 's/ /%20/g')
        encoded=$(echo ${encoded} | sed 's/!/%21/g')
        encoded=$(echo ${encoded} | sed 's/#/%23/g')
        encoded=$(echo ${encoded} | sed 's/\$/%24/g')
        encoded=$(echo ${encoded} | sed 's/&/%26/g')
        encoded=$(echo ${encoded} | sed 's/(/%28/g')
        encoded=$(echo ${encoded} | sed 's/)/%29/g')
        encoded=$(echo ${encoded} | sed 's/*/%2A/g')
        encoded=$(echo ${encoded} | sed 's/+/%2B/g')
        encoded=$(echo ${encoded} | sed 's#\/#%2F#g')
        encoded=$(echo ${encoded} | sed 's/:/%3A/g')
        encoded=$(echo ${encoded} | sed 's/;/%3B/g')
        encoded=$(echo ${encoded} | sed 's/</%3C/g')
        encoded=$(echo ${encoded} | sed 's/=/%3D/g')
        encoded=$(echo ${encoded} | sed 's/>/%3E/g')
        encoded=$(echo ${encoded} | sed 's/?/%3F/g')
        encoded=$(echo ${encoded} | sed 's/@/%40/g')
        encoded=$(echo ${encoded} | sed 's/\[/%5B/g')
        encoded=$(echo ${encoded} | sed 's/\\/%5C/g')
        encoded=$(echo ${encoded} | sed 's/]/%5D/g')
        encoded=$(echo ${encoded} | sed 's/\^/%5E/g')
        encoded=$(echo ${encoded} | sed 's/\`/%60/g')
        encoded=$(echo ${encoded} | sed 's/{/%7B/g')
        encoded=$(echo ${encoded} | sed 's/|/%7C/g')
        encoded=$(echo ${encoded} | sed 's/}/%7D/g')
        encoded=$(echo ${encoded} | sed 's/~/%7E/g')
        echo "${encoded}"
    }

### ToC
* [PayPal](#paypal)
* [Unzoner](#unzoner)
* [BitCoin](#bitcoin)
* [VPN](#vpn)
* [miscellaneous](miscellaneous)

### PayPal
> most of the calls implementing required PayPal API functionality

#### create billing agreement

    curl "${api_url}/paypal/billing-agreements/{{ balena_device_uuid|JWT.payload }}/create/{{ billing_type }}" \
      -H "X-Auth-Token: ${AUTH_TOKEN}"

#### execute billing agreement

    curl "${api_url}/paypal/billing-agreements/execute?token={{ paypal_token }}"

#### get billing agreement

    curl "${api_url}/paypal/billing-agreements/{{ billing_agreement }}" \
      -H "X-Auth-Token: ${AUTH_TOKEN}"

#### confirm active billing agreement

    curl "${api_url}/paypal/billing-agreements/{{ billing_agreement }}/confirm" \
      -H "X-Auth-Token: ${AUTH_TOKEN}"

#### get billing plans

    curl "${api_url}/paypal/billing-plans" \
      -H "X-Auth-Token: ${AUTH_TOKEN}"

#### get billing plan

    curl "${api_url}/paypal/billing-plans/{{ billing_plan }}" \
      -H "X-Auth-Token: ${AUTH_TOKEN}"

#### create billing plan

    curl "${api_url}/paypal/billing-plans/create/{{ billing_type }}" \
      -H "X-Auth-Token: ${AUTH_TOKEN}"

#### activate billing plan

    curl "${api_url}/paypal/billing-plans/{{ billing_plan }}/activate" \
      -H "X-Auth-Token: ${AUTH_TOKEN}"


### Unzoner
> most of the calls implementing core functionality

#### get ASNs

    curl "${api_url}/alpha/US/asns/common" \
      -H "X-Auth-Token: ${AUTH_TOKEN}"

#### get domains

    curl "${api_url}/alpha/US/domains/common,netflix" \
      -H "X-Auth-Token: ${AUTH_TOKEN}"

#### get default services

    curl "${api_url}/alpha/US/services/default/1" \
      -H "X-Auth-Token: ${AUTH_TOKEN}"

#### get optional services

    curl "${api_url}/alpha/US/services/default/0" \
      -H "X-Auth-Token: ${AUTH_TOKEN}"

#### get countries

##### all

    curl "${api_url}/countries/all" \
      -H "X-Auth-Token: ${AUTH_TOKEN}" | jq -r

##### available

    curl "${api_url}/countries/available" \
      -H "X-Auth-Token: ${AUTH_TOKEN}" | jq -r

##### available (flags)

    curl -I "${api_url}/countries/available/flags.png"

#### get country

    country="$(urlencode 'United Kingdom')"

    curl "${api_url}/country/${country}" \
      -H "X-Auth-Token: ${AUTH_TOKEN}"

#### get public node

	for af in 4 6; do
    	curl "${api_url}/node/${af}/country/${country}" \
      	  -H "X-Auth-Token: ${AUTH_TOKEN}"
    done

#### get private node

	for af in 4 6; do
	    curl "${api_url}/node/${af}/guid/{{ balena_device_uuid }}" \
    	  -H "X-Auth-Token: ${AUTH_TOKEN}"
	done

#### get closest public node by country and client geo

	for af in 4 6; do
	    ip="$(curl -${af} ifconfig.co/ip)"
    	curl "${api_url}/node/${af}/country/${country}/geo/${ip}" \
      	  -H "X-Auth-Token: ${AUTH_TOKEN}"
	done

#### put device info

    af=4
    type=4
    balena_device_uuid=$(uuid | sed 's/-//g')
    json=$(curl -s mgmt.${DNS_DOMAIN}/json)
    country=$(echo ${json} | jq -r .country)
    city=$(echo ${json} | jq -r .city)
    ip=$(echo ${json} | jq -r .ip)

    curl -X PUT "${api_url}/device/${type}/${balena_device_uuid}/${af}" \
      -H "X-Auth-Token: ${AUTH_TOKEN}" \
      -H 'Content-Type: application/json' \
      -d "{\"weight\":1,\"cipher\":null,\"auth\":null,\"upnp\":0,\"hostapd\":0,\"ip\":\"${ip}\",\"country\":\"${country}\",\"city\":\"${city}\",\"conns\":0,\"weight\":1,\"bytesin\":0,\"bytesout\":0,\"status\":1}"

#### get device info

	for af in 4 6; do
    	curl "${api_url}/device/${TYPE}/{{ balena_device_uuid }}/${af}" \
      	  -H "X-Auth-Token: ${AUTH_TOKEN}"
    done

#### get device bandwdith stats

	for af in 4 6; do
		for dt in 1 2 3 4 5; do
    		curl "${api_url}/device/${dt}/${balena_device_uuid}/${af}/stats" \
      	  	  -H "X-Auth-Token: ${AUTH_TOKEN}"
    	done
    done

#### put env var

    curl -X PUT "${api_url}/device/{{ balena_device_uuid }}/env" \
      -H 'Content-type: application/json' \
      -H "X-Auth-Token: ${AUTH_TOKEN}" \
      -d "{\"env_var_name\": \"${env_var_name}\", \"value\": \"${env_var_value}\"}"

#### get env vars

    curl "${api_url}/device/{{ balena_device_uuid }}/env" \
      -H "X-Auth-Token: ${AUTH_TOKEN}"

#### delete env var

    curl -X DELETE "${api_url}/env/${env_var_id}" \
      -H "X-Auth-Token: ${AUTH_TOKEN}"

#### update env var

    curl -X PATCH "${api_url}/env/${env_var_id}" \
      -H 'Content-type: application/json' \
      -H "X-Auth-Token: ${AUTH_TOKEN}" \
      -d "{\"value\": \"${env_var_value}\"}"

#### get device

    curl "${api_url}/device/{{ balena_device_uuid }}" \
      -H "X-Auth-Token: ${AUTH_TOKEN}"


### BitCoin
see, [application.py](src/application.py) and [bitcoin.py](src/bitcoin.py)


### VPN
> API calls implementing [VPN providers](https://github.com/Zomboided/service.vpn.manager.providers) database

#### get provider groups

    curl "${api_url}/vpnprovider/groups"

#### get providers

    curl "${api_url}/vpnproviders"

#### get providers by provider group

    curl "${api_url}/vpnproviders/group/{{ vpn_provider_group }}"

#### get location groups

    curl "${api_url}/vpnprovider/{{ vpn_provider }}/groups"

#### get locations by location group

    curl "${api_url}/vpnprovider/{{ vpn_provider }}/group/$(urlencode "{{ vpn_location_group }}")/locations"

#### get locations by location group and load
> NordVPN, IPVanish and PIA are the only supported providers currently

    curl "${api_url}/vpnprovider/{{ vpn_provider }}/group/$(urlencode "{{ vpn_location_group }}")/locations/load"

#### get locations by location group and geo-location
> NordVPN, IPVanish and PIA are the only supported providers currently

    curl "${api_url}/vpnprovider/{{ vpn_provider }}/group/$(urlencode "{{ vpn_location_group }}")/locations/geo/lat/{{ lattitude }}/lon/{{ longitude }}"

#### custom client/user cert required?

    curl "${api_url}/vpnprovider/{{ vpn_provider }}/usercert"

#### get profile

    curl "${api_url}/vpnprovider/{{ vpn_provider }}/group/$(urlencode "{{ vpn_location_group }}")/name/$(urlencode "{{ vpn_location_group }}")/profile"

#### update provider profiles
> `NordVPN`, `IPVanish` and `PIA` are currently supported

    curl "${api_url}/vpnprovider/{{ vpn_provider }}/update" \
      -H "X-Auth-Token: ${AUTH_TOKEN}"

#### install DD-WRT app
> ⏳ DD-WRT is currently private...

##### long version

    curl "${api_url}/ddwrt/group/{{ vpn_provider_group }}/provider/{{ vpn_provider }}/install"

##### short version (black.box defaults)
> To install on the router, pipe output to sh (e.g. `| sh`).

    curl "${API_HOST}/ddwrt"

##### download DD-WRT app

    curl "${api_url}/ddwrt/download" \
      -o ./ddwrt-mypage.tar.gz

##### get last commit (version)

    curl "${api_url}/ddwrt/version"


### miscellaneous 
> calls implementing dashboard functionality, such as `speedtest` and `IOtest`

#### video playback tests

##### get last test session

    curl "${api_url}/tests/sessions" \
      -H "X-Auth-Token: ${AUTH_TOKEN}"

##### get last entry in errors table

    curl "${api_url}/tests/errors" \
      -H "X-Auth-Token: ${AUTH_TOKEN}"

##### get last entry in screenshots table

    curl "${api_url}/tests/screenshots" \
      -H "X-Auth-Token: ${AUTH_TOKEN}"

##### get last entry in video diags table

    curl "${api_url}/tests/nflx_video_diags" \
      -H "X-Auth-Token: ${AUTH_TOKEN}"

##### get last test screenshot by country

    curl "${api_url}/screenshot/US" \
      -H "X-Auth-Token: ${AUTH_TOKEN}"

##### get last X screenshots with tags

    curl "${api_url}/screenshot/tags/10" \
      -H "X-Auth-Token: ${AUTH_TOKEN}"

#### speedtest

##### dequeue speedtest

    curl -I "${api_url}/speedtest/{{ balena_device_uuid }}" \
      -H "X-Auth-Token: ${AUTH_TOKEN}"

##### update speedtest

    curl -X PATCH "${api_url}/speedtest/{{ balena_device_uuid }}" \
      -H 'Content-type: application/json' \
      -H "X-Auth-Token: ${AUTH_TOKEN}" \
      -d "{\"status\":0,\"up\":\"0.0-12.6 sec 4.25 MBytes 2.84 Mbits/sec\",\"down\":\"0.0-11.1 sec 9.88 MBytes 7.46 Mbits/sec\"}"

#### IOtest

##### queue IOtest

    curl -X PUT "${api_url}/iotest/{{ test_id }}/guid/{{ balena_device_uuid }}"\
      -H "X-Auth-Token: ${AUTH_TOKEN}"

##### dequeue IOtest

    curl "${api_url}/iotest/queue/{{ balena_device_uuid }}"\
      -H "X-Auth-Token: ${AUTH_TOKEN}"

##### update IOtest

    curl -X PATCH "${api_url}/iotest/{{ balena_device_uuid }}" \
      -H 'Content-type: application/json' \
      -H "X-Auth-Token: ${AUTH_TOKEN}" \
      -d "{\"status\":0,\"result\":\"419430400 bytes (419 MB, 400 MiB) copied, 46.5299 s, 9.0 MB/s\",\"test\":{{ test_id }}}"

##### get IOtest

    curl "${api_url}/iotest/{{ test_id }}/guid/{{ balena_device_uuid }}" \
      -H "X-Auth-Token: ${AUTH_TOKEN}"
