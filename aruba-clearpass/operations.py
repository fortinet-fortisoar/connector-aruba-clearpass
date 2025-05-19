"""
Copyright start
MIT License
Copyright (c) 2025 Fortinet Inc
Copyright end
"""

import json
from requests import request, exceptions as req_exceptions
from .handle_token_auth import *
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('aruba-clearpass')

STATUS_MAPPING = {
    "Known": "known",
    "Unknown": "unknown",
    "Disabled": "disable"
}


def check_response(r):
    try:
        response_json = r.json()
    except Exception as e:
        msg_string = "Unable to parse reply as a JSON : {text}'".format(text=r.text)
        logger.exception("{}. Exception: {}".format(msg_string, str(e)))
        raise ConnectorError(msg_string)
    if r.ok:
        return response_json
    elif r.status_code == 404:  # Needed for API calls that are valid but have no content - e.g. query for specific device
        return None
    else:
        if isinstance(response_json, dict):
            logger.exception('Rest API failed with Error: {error}'.format(error=response_json))
            raise ConnectorError('{error}'.format(error=response_json))


def api_request(method, endpoint, connector_info, config, params=None, data=None, headers={}):
    try:
        ms = ArubaAuth(config)
        url = "{base_url}{endpoint}".format(base_url=ms.base_url, endpoint=endpoint)
        token = ms.validate_token(config, connector_info)
        headers['Authorization'] = token
        headers['Content-Type'] = 'application/json'  # need to check this
        try:
            response = request(method, url, headers=headers, params=params, data=json.dumps(data), verify=ms.verify_ssl)
            result = check_response(response)
            return result
        except req_exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except req_exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except req_exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except req_exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as err:
            raise ConnectorError(str(err))
    except Exception as err:
        raise ConnectorError(str(err))


def list_guests(config, params, connector_info):
    try:
        endpoint = "/api/guest"
        response = api_request("GET", endpoint, connector_info, config, params)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_guest_details(config, params, connector_info):
    try:
        guest_id = params.get('guest_id')
        endpoint = "/api/guest/{0}".format(guest_id)
        response = api_request("GET", endpoint, connector_info, config, params)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def list_sessions(config, params, connector_info):
    filter_string = params.pop('filter', None)
    if not filter_string:
        endpoint = "/api/session?calculate_count=true"
    else:
        endpoint = "/api/session?calculate_count=true&filter={0}".format(json.dumps(filter_string))
    try:
        response = api_request("GET", endpoint, connector_info, config, params)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def terminate_session(config, params, connector_info):
    try:
        session_id = params.get('session_id')
        payload = {
            "id": session_id,
            "confirm_disconnect": True
        }
        endpoint = "/api/session/{0}/disconnect".format(session_id)
        response = api_request("POST", endpoint, connector_info, config, params, data=payload)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def list_endpoints(config, params, connector_info):
    try:
        endpoint = "/api/endpoint"
        response = api_request("GET", endpoint, connector_info, config, params)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_endpoint_details(config, params, connector_info):
    try:
        endpoint_id = params.get('endpoint_id')
        endpoint = "/api/endpoint/{0}".format(endpoint_id)
        response = api_request("GET", endpoint, connector_info, config, params)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def build_payload(params):
    query = {}
    for k, v in params.items():
        if v != '':
            query[k] = STATUS_MAPPING.get(v, v)
    return query


def update_endpoint_status(config, params, connector_info):
    try:
        endpoint_id = params.get('endpoint_id')
        # endpoint_status = STATUS_MAPPING.get(params.get('endpoint_status'))
        params.pop('endpoint_id')
        payload = build_payload(params)
        endpoint = "/api/endpoint/{0}".format(endpoint_id)
        response = api_request("PATCH", endpoint, connector_info, config, params, data=payload)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def check_health(config, connector_info):
    try:
        ms = ArubaAuth(config)
        return ms.authorize(config, connector_info)
    except Exception as err:
        raise ConnectorError(str(err))


def get_device_profile(config, params, connector_info):
    try:
        mac_or_ip = params.get('mac_or_ip')
        endpoint = "/api/device-profiler/device-fingerprint/{0}".format(mac_or_ip)
        response = api_request("GET", endpoint, connector_info, config, params)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def disable_device(config, params, connector_info):
    try:
        mac_address = params.get('mac_address')
        payload = {
            "enabled": False
        }
        endpoint = "/api/device/mac/{0}".format(mac_address)
        response = api_request("PATCH", endpoint, connector_info, config, params, data=payload)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def session_coa_mac(config, params, connector_info):
    try:
        mac_address = params.get('mac_address')
        coa_profile = params.get('coa_profile')
        payload = {
            "enforcement_profile": [coa_profile]
        }
        endpoint = "/api/session-action/coa/mac/{0}?async=false".format(mac_address)
        response = api_request("POST", endpoint, connector_info, config, params, data=payload)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_endpoint_details_by_macaddress(config, params, connector_info):
    try:
        mac_address = params.get('mac_address')
        endpoint = "/api/endpoint/mac-address/{0}".format(mac_address)
        response = api_request("GET", endpoint, connector_info, config, params)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def block_endpoint(config, params, connector_info):
    try:
        mac_address = params.get('mac_address')
        payload = {
            "attributes": {
                "blacklisted": "true"}
        }
        endpoint = "/api/endpoint/mac-address/{0}".format(mac_address)
        response = api_request("PATCH", endpoint, connector_info, config, params, data=payload)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def execute_api_request(config, params, connector_info):
    endpoint = params.get('endpoint','')
    query_params = params.get('query_params',{})
    method = params.get('method', '')
    payload = params.get('payload')
    if not endpoint.startswith('/'):
        endpoint = f'/{endpoint}'
    return api_request(method, endpoint, connector_info, config, params=query_params, data=payload)



operations = {
    "list_guests": list_guests,
    "get_guest_details": get_guest_details,
    "list_endpoints": list_endpoints,
    "get_endpoint_details": get_endpoint_details,
    "update_endpoint_status": update_endpoint_status,
    "list_sessions": list_sessions,
    "terminate_session": terminate_session,
    "disable_device": disable_device,
    "session_coa_mac": session_coa_mac,
    "get_device_profile": get_device_profile,
    "get_endpoint_details_by_macaddress": get_endpoint_details_by_macaddress,
    "block_endpoint": block_endpoint,
    'execute_api_request': execute_api_request

}
