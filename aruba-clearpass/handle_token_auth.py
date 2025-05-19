"""
Copyright start
MIT License
Copyright (c) 2025 Fortinet Inc
Copyright end
"""

from time import time, ctime
from requests import request
from os import path
from datetime import datetime
from configparser import RawConfigParser
from base64 import b64encode, b64decode
from connectors.core.connector import get_logger, ConnectorError

CONFIG_SUPPORTS_TOKEN = True
try:
    from connectors.core.utils import update_connnector_config
except:
    CONFIG_SUPPORTS_TOKEN = False
    configfile = path.join(path.dirname(path.abspath(__file__)), 'config.conf')

logger = get_logger('aruba-clearpass')

REFRESH_TOKEN_FLAG = False
# grant types
PASSWORD_AUTHORIZATION_CODE = 'password'
CLIENT_SECRET_AUTHORIZATION_CODE = 'client_credentials'
REFRESH_TOKEN = 'refresh_token'
MAX_ATTEMPT = 3


class ArubaAuth:
    def __init__(self, config):
        self.base_url = config.get('host', '').strip('/')
        if not self.base_url.startswith('http') or not self.base_url.startswith('https'):
            self.base_url = 'https://' + self.base_url
        self.client_id = config.get('client_id', None)
        self.auth_grant_type = config.get('auth_grant_type')
        if self.auth_grant_type == 'Client Secret':
            self.client_secret = config.get('client_secret', None)
        else:
            self.user = config.get('username', None)
            self.password = config.get('password', None)
        self.verify_ssl = config.get('verify_ssl', None)
        self.token_url = '{0}/api/oauth'.format(self.base_url)
        self.scope = ''
        self.refresh_token = ''

    def convert_ts_epoch(self, ts):
        try:
            datetime_object = datetime.strptime(ctime(ts), '%a %b %d %H:%M:%S %Y')
        except:
            datetime_object = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S.%f')

        return datetime_object.timestamp()

    def encode_token(self, token):
        try:
            token = token.encode('UTF-8')
            return b64encode(token)
        except Exception as err:
            logger.error(err)

    def generate_token(self, REFRESH_TOKEN_FLAG):
        try:
            resp = self.acquire_token_on_behalf_of_user(REFRESH_TOKEN_FLAG)
            ts_now = time()
            resp['expires_in'] = (ts_now + float(resp['expires_in'])) if resp.get('expires_in') else None
            return resp
        except Exception as err:
            logger.error("{0}".format(err))
            raise ConnectorError("{0}".format(err))

    def write_config(self, token_resp, config, section_header):
        time_key = ['expires_in']
        token_key = ['access_token']
        config.add_section(section_header)
        for key, val in token_resp.items():
            if key not in time_key and key not in token_key:
                config.set(section_header, str(key), str(val))
        for key in time_key:
            config.set(section_header, str(key), self.convert_ts_epoch(token_resp['expires_in']))
        for key in token_key:
            config.set(section_header, str(key), self.encode_token(token_resp[key]).decode('utf-8'))

        try:
            with open(configfile, 'w') as fobj:
                config.write(fobj)
                fobj.close()
            return config
        except Exception as err:
            logger.error('{0}'.format(str(err)))
            raise ConnectorError('{0}'.format(str(err)))

    def handle_config(self, section_header, flag=False):
        # Lets setup the config parser.
        config = RawConfigParser()
        try:
            if path.exists(configfile) is False:
                token_resp = self.generate_token(REFRESH_TOKEN_FLAG)
                return self.write_config(token_resp, config, section_header)
            else:
                # Read existing config
                config.read(configfile)
                # Check for user
                if not config.has_section(section_header) and not flag:
                    # Write new config
                    token_resp = self.generate_token(REFRESH_TOKEN_FLAG)
                    return self.write_config(token_resp, config, section_header)
                else:
                    if flag:
                        config.remove_section(section_header)
                        with open(configfile, 'w') as f:
                            config.write(f)
                    else:
                        config.read(config)
                return config
        except Exception as err:
            logger.error('Handle_config:Failure {0}'.format(str(err)))
            raise ConnectorError(str(err))

    def validate_token(self, connector_config, connector_info):
        global REFRESH_TOKEN_FLAG
        if CONFIG_SUPPORTS_TOKEN:
            ts_now = time()
            if not connector_config.get('access_token'):
                logger.error('Error occurred while connecting server: Unauthorized')
                raise ConnectorError('Error occurred while connecting server: Unauthorized')
            expires = connector_config['expires_in']
            expires_ts = self.convert_ts_epoch(expires)
            if ts_now > float(expires_ts):
                if self.auth_grant_type == 'Username/Password':
                    REFRESH_TOKEN_FLAG = True
                logger.info('Token expired at {0}'.format(expires))
                self.refresh_token = connector_config['refresh_token']
                token_resp = self.generate_token(REFRESH_TOKEN_FLAG)
                connector_config['access_token'] = token_resp['access_token']
                connector_config['expires_in'] = token_resp['expires_in']
                if 'refresh_token' in token_resp:
                    connector_config['refresh_token'] = token_resp['refresh_token']
                update_connnector_config(connector_info['connector_name'], connector_info['connector_version'],
                                         connector_config,
                                         connector_config['config_id'])

                return 'Bearer {0}'.format(connector_config.get('access_token'))
            else:
                logger.info('Token is valid till {0}'.format(expires))
                return 'Bearer {0}'.format(connector_config.get('access_token'))
        else:
            client_id = connector_config.get('client_id')
            section_header = 'Aruba ClearPass: {0}'.format(client_id)
            time_key = ['expires_in']
            token_key = ['access_token']
            try:
                config = self.handle_config(section_header)
                ts_now = time()
                expires = config.get(section_header, 'expires_in')
                if ts_now > float(expires):
                    REFRESH_TOKEN_FLAG = True
                    self.refresh_token = config.get(section_header, 'refresh_token')
                    logger.info('Token expired at {0}'.format(str(expires)))
                    new_token = self.generate_token(REFRESH_TOKEN_FLAG)
                    for key, val in new_token.items():
                        if key in time_key:
                            config.set(section_header, str(key), self.convert_ts_epoch(new_token.get(key)))
                        if key in token_key:
                            config.set(section_header, str(key), self.encode_token(new_token[key]).decode('utf-8'))

                    with open(configfile, 'w') as fobj:
                        config.write(fobj)
                else:
                    logger.info('Token is valid till {0}'.format(str(expires)))

                encoded_token = config.get(section_header, 'access_token')
                decoded_token = b64decode(encoded_token.encode('utf-8'))
                token = 'Bearer {0}'.format(decoded_token.decode('utf-8'))
                return token
            except Exception as err:
                logger.error('{0}'.format(str(err)))
                raise ConnectorError('{0}'.format(str(err)))

    def remove_config(self):
        try:
            section_header = 'Aruba ClearPass: {0}'.format(self.client_id)
            self.handle_config(section_header, flag=True)
        except Exception as err:
            logger.error('{0}'.format(str(err)))
            raise ConnectorError('{0}'.format(str(err)))

    def acquire_token_on_behalf_of_user(self, REFRESH_TOKEN_FLAG, recursion_tries=0):
        try:
            post_data = {
                "client_id": self.client_id
            }
            if not REFRESH_TOKEN_FLAG:
                if self.auth_grant_type == 'Client Secret':
                    post_data['grant_type'] = CLIENT_SECRET_AUTHORIZATION_CODE
                    post_data['client_secret'] = self.client_secret
                else:
                    post_data['grant_type'] = PASSWORD_AUTHORIZATION_CODE
                    post_data['username'] = self.user
                    post_data['password'] = self.password
                    post_data['scope'] = self.scope
            else:
                if self.auth_grant_type == 'Client Secret':
                    post_data['grant_type'] = CLIENT_SECRET_AUTHORIZATION_CODE
                    post_data['client_secret'] = self.client_secret
                else:
                    post_data['grant_type'] = REFRESH_TOKEN
                    post_data['scope'] = self.scope
                    post_data['refresh_token'] = self.refresh_token
            logger.debug("Requested URL: [{0}] Query Data:[{1}]".format(self.token_url, post_data))
            response = request('POST', self.token_url, data=post_data, verify=self.verify_ssl)
            logger.debug("Response code: [{0}] Response URL: [{1}]".format(response.status_code, response.url))
            if response.status_code in [200, 204, 201]:
                return response.json()
            else:
                if response.text != "":
                    err = response.json()
                    err_msg = err.get('detail')
                    if err_msg == 'Invalid refresh token':
                        logger.debug("Generate refresh token")
                        if recursion_tries > MAX_ATTEMPT:
                            raise ConnectorError(err)
                        token_resp = self.acquire_token_on_behalf_of_user(REFRESH_TOKEN_FLAG=False, recursion_tries=+1)
                        return token_resp
                    logger.debug("Error Response: {0}".format(err))
                    raise ConnectorError(err)
                else:
                    error_msg = 'Response [{0}:{1}]'.format(response.status_code, response.reason)
                    raise ConnectorError(error_msg)
        except Exception as err:
            raise ConnectorError(err)

    def authorize(self, config, connector_info):
        if CONFIG_SUPPORTS_TOKEN:
            if not 'access_token' in config:
                token_resp = self.generate_token(REFRESH_TOKEN_FLAG=False)
                config['access_token'] = token_resp['access_token']
                config['expires_in'] = token_resp['expires_in']
                if 'refresh_token' in token_resp:
                    config['refresh_token'] = token_resp['refresh_token']
                update_connnector_config(connector_info['connector_name'], connector_info['connector_version'],
                                         config, config['config_id'])
                return True
            else:
                token_resp = self.validate_token(config, connector_info)
                return True
        else:
            self.remove_config()
            client_id = config.get('client_id')
            section_header = 'Aruba ClearPass: {0}'.format(client_id)
            self.handle_config(section_header)
            return True
