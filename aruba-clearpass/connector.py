"""
Copyright start
MIT License
Copyright (c) 2025 Fortinet Inc
Copyright end
"""

from connectors.core.connector import Connector, ConnectorError, get_logger
from .operations import *

logger = get_logger('aruba-clearpass')

class Aruba(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            connector_info = {"connector_name": self._info_json.get('name'),
                              "connector_version": self._info_json.get('version')}
            operation = operations.get(operation)
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)
        return operation(config, params, connector_info)


    def check_health(self, config):
        logger.info('starting health check')
        connector_info = {"connector_name": self._info_json.get('name'),
                          "connector_version": self._info_json.get('version')}
        check_health(config, connector_info)
        logger.info('completed health check no errors')