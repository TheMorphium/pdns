import re
import logging
import urllib.parse
import requests

import pdnsapi.cryptokey
from pdnsapi.cryptokey import CryptoKey
from pdnsapi.zone import Zone
from pdnsapi.metadata import ZoneMetadata

logger = logging.getLogger(__name__)


# FIXME: clients should not be doing this escaping. We need to switch this to the appropriate zone ID lookup API.
def _sanitize_dnsname(name):
    """
    Appends a dot to `name` if needed

    :param name: A DNS Name
    :return: A DNS Name that has a trailing dot
    :rtype: str
    """
    if name in ['.', '=2E']:
        # lol
        return '=2E'
    return f'{name}.' if name[-1] != '.' else name


class PDNSApi:
    """
    A wrapper-class that connects to the PowerDNS REST API to perform data manipulations

    TODO: We should probably try to do some caching
    """

    def __init__(self, apikey, version=1, baseurl='http://localhost:8081', server='localhost', timeout=2):
        """
        :param apikey: The API Key needed to access the API (`api-key` setting)
        :param version: The version of the API used, only 1 is supported at the moment
        :param baseurl: The URL where the lives, without the `/api....`
        :param server: The name of the server, 'localhost' by default. Use this when connecting to the API through e.g.
                       pdnscontrol or zone-control
        :param timeout: The timeout in seconds for a request
        :raises: ConnectionError when the API is not reachable
        """
        api_suffix = {
            0: '',
            1: '/api/v1',
        }[int(version)]
        url = f'{baseurl}{api_suffix}/servers/{server}'
        # Strip double (or more) slashes
        self.url = urllib.parse.urljoin(url, re.sub(r'/{2,}', '/', urllib.parse.urlparse(url).path))
        if apikey is None:
            raise Exception('apikey may not be None!')
        self.apikey = apikey
        self.timeout = timeout

        # needed for __repr__
        self._version = version
        self._baseurl = baseurl
        self._server = server

        # Test the API, raises in _do_request
        self._do_request('', 'GET')

    def __repr__(self):
        return f'{__name__}.PDNSApi(apikey="{self.apikey}", version={self._version}, baseurl="{self._baseurl}", server="{self._server}", timeout={self.timeout})'

    def _do_request(self, uri, method, data=None):
        """
        Does the actual API call.

        :param uri: Sub-path for the request, e.g. '/zones'
        :param method: HTTP method to use
        :param data: dict or list of data to send along with the request
        :return: a tuple containing the HTTP status code and the JSON response in Python format (i.e. list/dict)
        :rtype: tuple(int, str)
        """
        full_url = self.url + uri

        headers = {
            'Accept': 'application/json',
            'X-API-Key': self.apikey,
        }
        if data is not None:
            if not isinstance(data, (dict, list)):
                raise ValueError(
                    f'data was passed as a {type(data)}, needs to be dict or list!'
                )
            if method.upper() != 'GET':
                headers['Content-Type'] = 'application/json'

        logger.debug(f'Attempting {method} request to {full_url} with data: {data}')

        ret = None
        try:
            res = requests.request(method, full_url, headers=headers, json=data)
            try:
                ret = res.json()
            except ValueError:
                # We don't care that the response was empty
                pass
            res.raise_for_status()
            logger.debug(f"Success! Got a {res.status_code} response with data: {ret}")
            return res.status_code, ret
        except requests.ConnectionError as e:
            logger.debug(f"Got a Connection error: {str(e)}")
            raise ConnectionError(f"Unable to connect to {full_url}: {e}")
        except requests.HTTPError as e:
            logger.debug(f"Got an HTTP {e.response.status_code} Error: {ret}")
            raise ConnectionError(
                f"HTTP error code {e.response.status_code} received for {e.request.url}: {ret.get('error', ret)}"
            )
        except Exception as e:
            msg = f"Error doing {method} request to {full_url}: {e}"
            logger.debug(msg)
            raise ConnectionError(msg)

    def get_cryptokeys(self, zone):
        """
        Get all CryptoKeys for `zone`

        :param str zone: The zone to get the keys for
        :return: All the cryptokeys for the zone
        :rtype: list(CryptoKey)
        """
        code, resp = self._do_request(
            f'/zones/{_sanitize_dnsname(zone)}/cryptokeys', 'GET'
        )

        if code == 200:
            cryptokeys = []
            for k in resp:
                k.pop('type')
                cryptokeys.append(CryptoKey(**k))
            return cryptokeys

        raise Exception(f'Unexpected response: {code}: {resp}')

    def get_cryptokey(self, zone, cryptokey):
        """
        Gets a single CryptoKey

        :param zone: The zone name
        :param cryptokey: The id of the key or a :class:`CryptoKey <pdnsapi.cryptokey.CryptoKey>`, when the latter is provided, only the ``id`` field
                           is read
        :return: a :class:`pdnsapi.cryptokey.CryptoKey`
        """
        keyid = -1
        if isinstance(cryptokey, CryptoKey):
            keyid = cryptokey.id
        if isinstance(cryptokey, (str, int)):
            keyid = cryptokey
        if keyid == -1:
            raise Exception("cryptokey is not a CryptoKey, nor a str or int")

        code, resp = self._do_request(
            f'/zones/{_sanitize_dnsname(zone)}/cryptokeys/{keyid}', 'GET'
        )

        if code == 200:
            resp.pop('type')
            return CryptoKey(**resp)

        raise Exception(f'Unexpected response: {code}: {resp}')

    def set_cryptokey_active(self, zone, cryptokey, active=True):
        """
        Sets the `active` field of a CryptoKey

        :param zone: The name of the zone
        :param cryptokey: The :class:`pdnsapi.cryptokey.CryptoKey` or a string of the `id` field
                          Note: the `active`-field of this object is ignored!
        :param active: A boolean for the `active` field
        :return: the new :class:`pdnsapi.cryptokey.Cryptokey`
        :raises: Exception on failure
        """
        keyid = -1
        if isinstance(cryptokey, CryptoKey):
            keyid = cryptokey.id
        if isinstance(cryptokey, (str, int)):
            keyid = int(cryptokey)
        if keyid == -1:
            raise Exception("cryptokey is not a CryptoKey, nor a str or int")

        code, resp = self._do_request(
            f'/zones/{_sanitize_dnsname(zone)}/cryptokeys/{keyid}',
            'PUT',
            {'active': active},
        )
        if code == 422:
            raise Exception(
                f"Failed to set cryptokey {keyid} in zone {zone} to {'active' if active else 'inactive'}: {resp}"
            )
        if code == 204:
            return self.get_cryptokey(zone, cryptokey)

        raise Exception(f'Unexpected response: {code}: {resp}')

    def set_cryptokey_published(self, zone, cryptokey, published=True):
        """
        Sets the `published` field of a CryptoKey

        :param zone: The name of the zone
        :param cryptokey: The :class:`pdnsapi.cryptokey.CryptoKey` or a string of the `id` field
        :param published: A boolean for the `published` field
        :return: the new :class:`pdnsapi.cryptokey.Cryptokey`
        :raises: Exception on failure
        """
        keyid = -1
        if isinstance(cryptokey, CryptoKey):
            keyid = cryptokey.id
        if isinstance(cryptokey, (str, int)):
            keyid = int(cryptokey)
        if keyid == -1:
            raise Exception("cryptokey is not a CryptoKey, nor a str or int")

        code, resp = self._do_request(
            f'/zones/{_sanitize_dnsname(zone)}/cryptokeys/{keyid}',
            'PUT',
            {'published': published, 'active': True},
        )
        if code == 422:
            raise Exception(
                f"Failed to set cryptokey {keyid} in zone {zone} to {'published' if published else 'unpublished'}: {resp}"
            )
        if code == 204:
            return self.get_cryptokey(zone, cryptokey)

        raise Exception(f'Unexpected response: {code}: {resp}')

    def publish_cryptokey(self, zone, cryptokey):

        return  self.set_cryptokey_published(zone, cryptokey, published=True)

    def unpublish_cryptokey(self, zone, cryptokey):

        return  self.set_cryptokey_published(zone, cryptokey, published=False)

    def delete_cryptokey(self, zone, cryptokey):
        """
        Removes a cryptokey

        :param zone: The name of the zone
        :param cryptokey: The :class:`pdnsapi.zone.CryptoKey` or a string of the `id` field
                          Note: the `active`-field of this object is ignored!
        :return: On success
        :raises: Exception on failure
        """
        keyid = -1
        if isinstance(cryptokey, CryptoKey):
            keyid = cryptokey.id
        if isinstance(cryptokey, (str, int)):
            keyid = cryptokey
        if keyid == -1:
            raise Exception("cryptokey is not a CryptoKey, nor a str or int")
        code, resp = self._do_request(
            f'/zones/{_sanitize_dnsname(zone)}/cryptokeys/{keyid}', 'DELETE'
        )
        if code == 422:
            raise Exception(f'Failed to remove cryptokey {keyid} in zone {zone}: {resp}')
        if code == 204:
            return

        raise Exception(f'Unexpected response: {code}: {resp}')

    def add_cryptokey(self, zone, keytype='zsk', active=False, content=None, algo=None, bits=None, published=True):
        """
        Adds a CryptoKey to zone. If content is None, a new key is generated by the server, using algorithm from `algo`
        and a size of `bits` (if applicable). If `content` and `algo` are both None, the server default is used (in
        4.0.X, this is algorithm 13, ECDSAP256SHA256)

        :param zone: The zone for which to create the key
        :param keytype: Either 'ksk' or 'zsk'
        :param active: Bool whether or not the new key should be active
        :param content: An ISC encoded private key.
        :param algo: An integer or lowercase DNSSEC algorithm name
        :param bits: The size of the key
        :return: The created CryptoKey on success
        :raises: an Exception on failure
        """

        data = {'active': active,
                'keytype': keytype,
                'published': published}

        if content is not None:
            data['content'] = content

        if algo is not None:
            algo = pdnsapi.cryptokey.shorthand_to_algo.get(algo, algo)
            data['algorithm'] = algo

        if bits is not None:
            data['bits'] = bits

        code, resp = self._do_request(
            f'/zones/{_sanitize_dnsname(zone)}/cryptokeys', 'POST', data
        )

        if code == 422:
            raise Exception(f'Unable to create CryptoKey in zone {zone}: {resp}')
        if code == 201:
            resp.pop('type')
            return CryptoKey(**resp)

        raise Exception(f'Unexpected response: {code}: {resp}')

    def get_zones(self):
        """
        Get all zones

        :return: All zones ons the server
        :rtype: list(:class:`pdnsapi.zone.Zone`)
        """
        code, resp = self._do_request('/zones',
                                      'GET')
        if code == 200:
            return [Zone(**zone) for zone in resp]

        raise Exception(f'Unexpected response: {code}: {resp}')

    def get_zone(self, zone):
        """
        Gets the full zone contents

        :param str zone: The zone we want the full contents for
        :return: a :class:`pdnsapi.zone.Zone`
        """
        code, resp = self._do_request(f'/zones/{_sanitize_dnsname(zone)}', 'GET')

        if code == 200:
            return Zone(**resp)

        raise Exception(f'Unexpected response: {code}: {resp}')

    def bump_soa(self, zone, serial=None):
        """
        Bump zone SOA serial number

        :param str zone: The zone we want to bump
        :param str serial: The new serial otherwise will update to existing serial+1
        :return: a :class:`pdnsapi.zone.Zone`
        """

        content = self.get_zone(zone)
        soa = next((rrset for rrset in content.rrsets if rrset.rtype == "SOA"), None)
        if soa is None:
            raise Exception('No such SOA record')


        newcontent = soa.records[0].content.split(" ")
        newcontent[2] = serial if serial != None else str(int(newcontent[2]) + 1)
        code, resp = self._do_request(
            f'/zones/{_sanitize_dnsname(zone)}',
            'PATCH',
            {
                "rrsets": [
                    {
                        "name": soa.name,
                        "type": soa.rtype,
                        "ttl": soa.ttl,
                        "changetype": "REPLACE",
                        "records": [
                            {
                                "content": " ".join(newcontent),
                                "disabled": soa.records[0].disabled,
                            }
                        ],
                    }
                ]
            },
        )

        if code == 204:
            return self.get_zone(zone)

        raise Exception(f'Unexpected response: {code}: {resp}')

    def set_zone_param(self, zone, param, value):
        """

        :param zone:
        :param param:
        :param value:
        :return:
        """
        zonename = _sanitize_dnsname(zone)
        code, resp = self._do_request(f'/zones/{zonename}', 'PUT', {param: value})

        if code == 204:
            return self.get_zone(zonename)

        raise Exception(f'Unexpected response: {code}: {resp}')

    def get_zone_metadata(self, zone, kind=''):
        """
        Gets zone metadata

        :param zone: The zone for which to retrieve the meta data
        :param kind: The zone metadata kind to retrieve. If this is an empty string, all zone metadata is retrieved
        :return: A list of :class:`pdnsapi.metadata.ZoneMetadata` objects
        """
        code, resp = self._do_request(
            f"/zones/{_sanitize_dnsname(zone)}/metadata{f'/{kind}' if len(kind) else ''}",
            'GET',
        )

        if code == 200:
            if kind == '':
                return [ZoneMetadata(r['kind'], r['metadata']) for r in resp]
            else:
                return ZoneMetadata(resp['kind'], resp['metadata'])

        raise Exception(f'Unexpected response: {code}: {resp}')

    def set_zone_metadata(self, zone, kind, metadata):
        if not isinstance(metadata, list):
            metadata = [metadata]
        obj = {'metadata': metadata}
        code, resp = self._do_request(
            f'/zones/{_sanitize_dnsname(zone)}/metadata/{kind}', 'PUT', obj
        )

        if code == 422:
            raise Exception(
                f'Failed to set metadata {kind} in zone {zone} to {metadata}: {resp}'
            )
        if code == 200:
            return ZoneMetadata(resp['kind'], resp['metadata'])

        raise Exception(f'Unexpected response: {code}: {resp}')

    def delete_zone_metadata(self, zone, kind):
        code, resp = self._do_request(
            f'/zones/{_sanitize_dnsname(zone)}/metadata/{kind}', 'DELETE'
        )

        if code == 422:
            raise Exception(f'Failed to remove metadata {kind} in zone {zone}: {resp}')
        if code == 200:
            return

        raise Exception(f'Unexpected response: {code}: {resp}')
