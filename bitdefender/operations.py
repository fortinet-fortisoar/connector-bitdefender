import json
import base64
import requests
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('bitdefender')

error_msgs = {
    400: 'Bad/Invalid Request',
    401: 'Unauthorized: Invalid credentials provided failed to authorize',
    403: 'Access Denied',
    404: 'Not Found',
    500: 'Internal Server Error',
    503: 'Service Unavailable',
    'time_out': 'The request timed out while trying to connect to the remote server',
    'ssl_error': 'SSL certificate validation failed'
}


class BitDefender(object):
    def __init__(self, config, *args, **kwargs):
        self.server_url = config.get('server_url')
        self.apiKey = config.get('token')
        self.company_id = config.get('company_id')
        url = config.get('server_url').strip('/')
        if not url.startswith('https://') and not url.startswith('http://'):
            self.url = 'https://{0}/'.format(url)
        else:
            self.url = url + '/'
        self.ssl_verify = config.get('verify_ssl')

    def make_rest_call(self, url, method='POST', action=None, params=None):
        try:
            loginString = self.apiKey + ":"
            encodedBytes = base64.b64encode(loginString.encode())
            encodedUserPassSequence = str(encodedBytes, 'utf-8')
            authorizationHeader = "Basic " + encodedUserPassSequence

            url = self.url + 'api/v1.0/jsonrpc/' + url
            header = {"Content-Type": "application/json",
                      "Authorization": authorizationHeader}

            request = {"params": params, "jsonrpc": "2.0",
                       "method": action, "id": self.company_id}

            logger.info(f"Request URL: {url}")
            logger.info(
                f"Final request payload: {json.dumps(request, indent=2)}")

            response = requests.request(
                method, url, json=request, verify=self.ssl_verify, headers=header)

            if response.ok or response.status_code == 204:
                logger.info(f'Successfully got response for url {url}')
                if 'json' in str(response.headers):
                    return response.json()
            else:
                if error_msgs.get(response.status_code):
                    logger.error(
                        f"Error: {error_msgs.get(response.status_code)}")
                    raise ConnectorError(
                        f"{error_msgs.get(response.status_code)}")
                else:
                    response_json = response.json()
                    logger.error(response_json)
                    raise ConnectorError(response_json)
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError(
                'The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                'The server did not send any data in the allotted amount of time')
        except Exception as err:
            raise ConnectorError(str(err))


def build_payload(payload):
    payload = {k: v for k, v in payload.items() if v is not None and v != ''}
    return payload


def get_computers_quarantine_items_list(config, params):
    try:
        bd = BitDefender(config)
        url = 'quarantine/computers'
        params = build_payload(params)
        response = bd.make_rest_call(
            url=url, method='POST', action='getQuarantineItemsList', params=params)
        if response:
            return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_exchange_quarantine_items_list(config, params):
    try:
        bd = BitDefender(config)
        url = 'quarantine/exchange'
        params = build_payload(params)
        response = bd.make_rest_call(
            url=url, method='POST', action='getQuarantineItemsList', params=params)
        if response:
            return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_accounts_list(config, params):
    try:
        bd = BitDefender(config)
        url = 'accounts'
        params = build_payload(params)
        response = bd.make_rest_call(
            url=url, method='POST', action='getAccountsList', params=params)
        if response:
            return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_policies_list(config, params):
    try:
        bd = BitDefender(config)
        url = 'policies'
        params = build_payload(params)
        response = bd.make_rest_call(
            url=url, method='POST', action='getPoliciesList', params=params)
        if response:
            return response
    except Exception as err:
        logger.exception(f"Error in get_policies_list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")


def add_to_blocklist(config, params):
    try:
        bd = BitDefender(config)
        url = 'incidents'
        if params.get('type') == 'MD5':
            hash_type = 2
        else:
            hash_type = 1
        payload = {
            "hashType": hash_type,
            "hashList": [params.get('hash')],
            "sourceInfo": params.get('sourceinfo')
        }
        response = bd.make_rest_call(
            url=url, method='POST', action='addToBlocklist', params=payload)
        if response:
            return response
    except Exception as err:
        logger.exception(f"Error in get_policies_list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")


def get_block_list_items(config, params):
    try:
        bd = BitDefender(config)
        url = 'incidents'
        payload = {
            "page": params.get('page'),
            "perPage": params.get('perPage')
        }
        response = bd.make_rest_call(
            url=url, method='POST', action='getBlocklistItems', params=payload)
        if response:
            return response
    except Exception as err:
        logger.exception(f"Error in get_policies_list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")


def remove_from_blocklist(config, params):
    try:
        bd = BitDefender(config)
        url = 'incidents'
        payload = {
            "hashItemId": params.get('hashItemId')
        }
        response = bd.make_rest_call(
            url=url, method='POST',
            action='removeFromBlocklist', params=payload)
        if response:
            return response
    except Exception as err:
        logger.exception(f"Error in get_policies_list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")


def create_isolate_endpointtask(config, params):
    try:
        bd = BitDefender(config)
        url = 'incidents'
        payload = {
            "endpointId": params.get('endpointId')
        }
        response = bd.make_rest_call(
            url=url, method='POST',
            action='createIsolateEndpointTask', params=payload)
        if response:
            return response
    except Exception as err:
        logger.exception(f"Error in get_policies_list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")


def createRestoreEndpointFromIsolationTask(config, params):
    try:
        bd = BitDefender(config)
        url = 'incidents'
        payload = {
            "endpointId": params.get('endpointId')
        }
        response = bd.make_rest_call(
            url=url, method='POST',
            action='createRestoreEndpointFromIsolationTask', params=payload)
        if response:
            return response
    except Exception as err:
        logger.exception(f"Error in get_policies_list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")


def get_custom_rule_list(config, params):
    try:
        bd = BitDefender(config)
        url = 'incidents'
        if params.get('type') == "Detection":
            type1 = 1
        else:
            type1 = 2
        payload = {
            "companyId": params.get('companyid'),
            "type": type1,
            "page": params.get('page'),
            "perPage": params.get('perPage')
        }
        response = bd.make_rest_call(
            url=url, method='POST',
            action='getCustomRulesList', params=payload)
        if response:
            return response
    except Exception as err:
        logger.exception(f"Error in get_policies_list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")


def delete_custom_rule(config, params):
    try:
        bd = BitDefender(config)
        url = 'incidents'
        if params.get('type') == "Detection":
            type1 = 1
        else:
            type1 = 2
        payload = {
            "ruleId": params.get('ruleId'),
            "type": type1
        }
        response = bd.make_rest_call(
            url=url, method='POST',
            action='deleteCustomRule', params=payload)
        if response:
            return response
    except Exception as err:
        logger.exception(f"Error in get_policies_list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")


def update_incident_note(config, params):
    try:
        bd = BitDefender(config)
        url = 'incidents'
        if params.get('type') == "incidents":
            type1 = 'incidents'
        else:
            type1 = 'extendedIncidents'
        payload = {
            "incidentId": params.get('incident_id'),
            "type": type1,
            "note": params.get('note')
        }
        response = bd.make_rest_call(
            url=url, method='POST',
            action='updateIncidentNote', params=payload)
        if response:
            return response
    except Exception as err:
        logger.exception(f"Error in get_policies_list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")


def change_incident_status(config, params):
    try:
        bd = BitDefender(config)
        url = 'incidents'
        if params.get('type') == "incidents":
            type1 = 'incidents'
        else:
            type1 = 'extendedIncidents'
        if params.get('status') == "Open":
            status = 1
        elif params.get('status') == "Investigating":
            status = 2
        elif params.get('status') == "Closed":
            status = 3
        else:
            status = 4

        payload = {
            "type": type1,
            "incidentId": params.get('incident_id'),
            "status": status
        }
        response = bd.make_rest_call(
            url=url, method='POST',
            action='changeIncidentStatus', params=payload)
        if response:
            return response
    except Exception as err:
        logger.exception(f"Error in get_policies_list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")


def get_endpoints_list(config, params):
    try:
        bd = BitDefender(config)
        url = 'network'

        payload = {
        }
        response = bd.make_rest_call(
            url=url, method='POST',
            action='getEndpointsList', params=payload)
        if response:
            return response
    except Exception as err:
        logger.exception(f"Error in get_policies_list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")


def get_managed_endpoints_details(config, params):
    try:
        bd = BitDefender(config)
        url = 'network'

        payload = {
            "endpointId": params.get('endpointId')
        }
        response = bd.make_rest_call(
            url=url, method='POST',
            action='getManagedEndpointDetails', params=payload)
        if response:
            return response
    except Exception as err:
        logger.exception(f"Error in get_policies_list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")


def move_endpoints(config, params):
    try:
        bd = BitDefender(config)
        url = 'network'

        payload = {
            "endpointIds": [params.get('endpointId')],
            "groupId": params.get('groupId')
        }
        response = bd.make_rest_call(
            url=url, method='POST',
            action='moveEndpoints', params=payload)
        if response:
            return response
    except Exception as err:
        logger.exception(f"Error in get_policies_list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")


def set_endpoint_label(config, params):
    try:
        bd = BitDefender(config)
        url = 'network'

        payload = {
            "endpointId": params.get('endpointId'),
            "label": params.get('label')
        }
        response = bd.make_rest_call(
            url=url, method='POST',
            action='setEndpointLabel', params=payload)
        if response:
            return response
    except Exception as err:
        logger.exception(f"Error in get_policies_list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")


def create_scan_task(config, params):
    try:
        bd = BitDefender(config)
        url = 'network'
        if params.get('type') == "Quick Scan":
            type1 = 1
        elif params.get('type') == "Full Scan":
            type1 = 2
        else:
            type1 = 3
        if params.get('returnAllTaskIds') == "True":
            settask = True
        else:
            settask = False

        payload = {
            "targetIds": [params.get('targetIds')],
            "type": type1,
            "name": params.get('name'),
            "returnAllTaskIds": settask
        }
        response = bd.make_rest_call(
            url=url, method='POST',
            action='createScanTask', params=payload)
        if response:
            return response
    except Exception as err:
        logger.exception(f"Error in get_policies_list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")


def create_scan_task_by_mac(config, params):
    try:
        bd = BitDefender(config)
        url = 'network'
        if params.get('type') == "Quick Scan":
            type1 = 1
        elif params.get('type') == "Full Scan":
            type1 = 2
        else:
            type1 = 3
        if params.get('returnAllTaskIds') == "True":
            settask = "true"
        else:
            settask = "false"
        payload = {
            "macAddresses": [params.get('macAddresses')],
            "type": type1,
            "name": params.get('name'),
            "returnAllTaskIds": settask
        }
        response = bd.make_rest_call(
            url=url, method='POST',
            action='createScanTaskByMac', params=payload)
        if response:
            return response
    except Exception as err:
        logger.exception(f"Error in get_policies_list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")


def get_scan_tasks_list(config, params):
    try:
        bd = BitDefender(config)
        url = 'network'
        if params.get('status') == "Pending":
            status1 = 1
        elif params.get('status') == "In progress":
            status1 = 2
        elif params.get('status') == "Finished":
            status1 = 3
        else:
            status1 = 4
        payload = {
            "status": status1,
            "page": params.get('page'),
            "perPage": params.get('perPage')
        }
        response = bd.make_rest_call(
            url=url, method='POST',
            action='getScanTasksList', params=payload)
        if response:
            return response
    except Exception as err:
        logger.exception(f"Error in get_policies_list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")


def get_scan_tasks_status(config, params):
    try:
        bd = BitDefender(config)
        url = 'network'
        payload = {
            "taskId": params.get('taskId')
        }
        response = bd.make_rest_call(
            url=url, method='POST',
            action='getTaskStatus', params=payload)
        if response:
            return response
    except Exception as err:
        logger.exception(f"Error in get_policies_list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")


def create_add_file_to_quarantine_task(config, params):
    try:
        bd = BitDefender(config)
        url = 'quarantine'
        payload = {
            "endpointIds": [params.get('endpointIds')],
            "filePath": params.get('filePath')
        }
        response = bd.make_rest_call(
            url=url, method='POST',
            action='createAddFileToQuarantineTask', params=payload)
        if response:
            return response
    except Exception as err:
        logger.exception(f"Error in get_policies_list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")
        raise ConnectorError(f"Failed to get policies list: {str(err)}")


def _check_health(config):
    try:
        bd = BitDefender(config)
        url = 'network'
        params = {}
        response = bd.make_rest_call(
            url=url, method='POST', action='getEndpointsList', params=params)
        if response:
            return response
    except Exception as err:
        logger.exceptions(str(err))
        raise ConnectorError(str(err))


operations = {
    'get_computers_quarantine_items_list': get_computers_quarantine_items_list,
    'get_exchange_quarantine_items_list': get_exchange_quarantine_items_list,
    'get_accounts_list': get_accounts_list,
    'get_policies_list': get_policies_list,
    'add_to_blocklist': add_to_blocklist,
    'get_block_list_items': get_block_list_items,
    'remove_from_blocklist': remove_from_blocklist,
    'create_isolate_endpointtask': create_isolate_endpointtask,
    'get_custom_rule_list': get_custom_rule_list,
    'delete_custom_rule': delete_custom_rule,
    'update_incident_note': update_incident_note,
    'change_incident_status': change_incident_status,
    'get_endpoints_list': get_endpoints_list,
    'get_managed_endpoints_details': get_managed_endpoints_details,
    'move_endpoints': move_endpoints,
    'set_endpoint_label': set_endpoint_label,
    'create_scan_task': create_scan_task,
    'create_scan_task_by_mac': create_scan_task_by_mac,
    'get_scan_tasks_list': get_scan_tasks_list,
    'get_scan_tasks_status': get_scan_tasks_status,
    'create_add_file_to_quarantine_task': create_add_file_to_quarantine_task
}
