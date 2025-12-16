"""
DNAC Discovery Script.
Copyright (c) 2021 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
               https://developer.cisco.com/docs/licenses
All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

__author__ = "Phithakkit Phasuk"
__email__ = "phphasuk@cisco.com"
__version__ = "0.1.52"
__copyright__ = "Copyright (c) 2021 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"


import urllib3
import requests
import json
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning
import logging
import time


class rest_api_lib:
    def __init__(self, dnac_ip, dnac_port, username, password):
        urllib3.disable_warnings(InsecureRequestWarning)  # disable insecure https warnings
        self.dnac_ip = dnac_ip
        self.dnac_port = dnac_port
        self.username = username
        self.password = password
        # Initialize rate limiting variables
        self._request_count = 0
        self._rate_limit_start_time = time.time()
        self._last_request_time = 0
        self.get_token()


    def get_token(self):
        url = 'https://%s:%s/dna/system/api/v1/auth/token'%(self.dnac_ip, self.dnac_port)
        auth = HTTPBasicAuth(self.username, self.password)
        headers = {'content-type' : 'application/json'}
        try:
            response = requests.post(url, auth=auth, headers=headers, verify=False)
            response.raise_for_status()
            token = response.json()['Token']
            logging.info('Got Token from DNAC')
            logging.debug(f'Token: {token}')
            self.token = token
            self.token_time = time.time()
            return
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            raise SystemExit()

    def logout(self):
        """Logout from dnac"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded', 'X-XSRF-TOKEN': self.token}
        url = "https://%s:%s/logout?nocache"%(self.dnac_ip, self.dnac_port)
        try:
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            logging.info(f'Logout from DNAC successful')
            logging.debug(f'Logout from DNAC successful response: {response}')
            return
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            raise SystemExit()

    def get_tasks_by_id(self, task_id):
        """
        Get task by ID.
        
        Returns the task with the given ID.
        
        Args:
            task_id (str): The ID of the task to retrieve (required)
            
        Returns:
            dict: Task information or None if not found
        """
        # Rate limiting check
        current_time = time.time()
        time_elapsed = current_time - self._rate_limit_start_time
        
        # Reset counter every 60 seconds
        if time_elapsed >= 60:
            self._request_count = 0
            self._rate_limit_start_time = current_time
        
        # Check if we've hit the rate limit (50 requests per minute)
        if self._request_count >= 50:
            sleep_time = 60 - time_elapsed
            if sleep_time > 0:
                logging.info(f'Rate limit reached. Sleeping for {sleep_time:.2f} seconds...')
                time.sleep(sleep_time)
                self._request_count = 0
                self._rate_limit_start_time = time.time()
        
        # Ensure minimum interval between requests (1.2 seconds)
        time_since_last_request = current_time - self._last_request_time
        if time_since_last_request < 1.2:
            time.sleep(1.2 - time_since_last_request)
        
        self._request_count += 1
        self._last_request_time = time.time()
        
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        
        headers = {
            'x-auth-token': self.token,
            'content-type': 'application/json'
        }
        
        url = f"https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/tasks/{task_id}"
        
        try:
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            result = response.json()
            
            logging.info(f'Got task by ID: {task_id}')
            logging.debug(f'Task response: {result}')
            
            return result.get('response')
            
        except requests.exceptions.HTTPError as err:
            if err.response and err.response.status_code == 404:
                logging.warning(f'Task not found: {task_id}')
            else:
                logging.error(f'HTTP error getting task by ID: {err}')
            logging.debug(f'Response: {err.response.text if err.response else "No response"}')
            return None
        except Exception as err:
            logging.error(f'Error getting task by ID: {err}', exc_info=True)
            return None
    
    def get_task_info(self, tid): #sunset
        """
        Get information for a specific task by ID.
        This is a convenience wrapper around get_tasks for backward compatibility.
        
        Args:
            tid (str): Task ID
            
        Returns:
            dict: Task information or None if not found
        """
        # Use the task/{id} endpoint for single task lookup
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = {
                'x-auth-token': self.token,
                'content-type': 'application/json'}
        url = f"https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/task/{tid}"
        try:
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            info = response.json()['response']
            logging.info(f'Got Task Info for: {tid}')
            logging.debug(f'Task Info: {info}')
            return info
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            return None
        except Exception as err:
            logging.error(err, exc_info=True)
            return None
    
    def get_task_detail_by_id(self, task_id):
        """
        Get detailed task information by task ID.
        
        Returns detailed task information including result location and execution details.
        The detail endpoint provides more comprehensive information than the basic task endpoint.
        
        Args:
            task_id (str): The ID of the task to retrieve details for (required)
            
        Returns:
            dict: Detailed task information or None if not found
        """
        # Rate limiting check
        current_time = time.time()
        time_elapsed = current_time - self._rate_limit_start_time
        
        # Reset counter every 60 seconds
        if time_elapsed >= 60:
            self._request_count = 0
            self._rate_limit_start_time = current_time
        
        # Check if we've hit the rate limit (50 requests per minute)
        if self._request_count >= 50:
            sleep_time = 60 - time_elapsed
            if sleep_time > 0:
                logging.info(f'Rate limit reached. Sleeping for {sleep_time:.2f} seconds...')
                time.sleep(sleep_time)
                self._request_count = 0
                self._rate_limit_start_time = time.time()
        
        # Ensure minimum interval between requests (1.2 seconds)
        time_since_last_request = current_time - self._last_request_time
        if time_since_last_request < 1.2:
            time.sleep(1.2 - time_since_last_request)
        
        self._request_count += 1
        self._last_request_time = time.time()
        
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        
        headers = {
            'x-auth-token': self.token,
            'content-type': 'application/json'
        }
        
        url = f"https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/tasks/{task_id}/detail"
        
        try:
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            result = response.json()
            
            logging.info(f'Got task detail by ID: {task_id}')
            logging.debug(f'Task detail response: {result}')
            
            return result.get('response')
            
        except requests.exceptions.HTTPError as err:
            if err.response and err.response.status_code == 404:
                logging.warning(f'Task detail not found: {task_id}')
            else:
                logging.error(f'HTTP error getting task detail by ID: {err}')
            logging.debug(f'Response: {err.response.text if err.response else "No response"}')
            return None
        except Exception as err:
            logging.error(f'Error getting task detail by ID: {err}', exc_info=True)
            return None

    def get_discovery_info(self, did):
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = {
                'x-auth-token': self.token,
                'content-type': 'application/json'}
        url = f"https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/discovery/{did}"
        try:
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            info = response.json()['response']
            logging.info(f'Got Discovery Info for: {did}')
            logging.debug(f'Task Info: {info}')
            return info
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            raise SystemExit()


    def get_discovery_result(self, did):
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = { 'x-auth-token': self.token,
                    'content-type': 'application/json' }
        url = f"https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/discovery/{did}/network-device"
        try:
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            info = response.json()['response']
            logging.info(f'Got Discovery Result for: {did}')
            logging.debug(f'Task Info: {info}')
            return info
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            raise SystemExit()


    def delete_alldiscovery(self):
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = {
                'x-auth-token': self.token,
                'content-type': 'application/json'}
        url = f"https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/discovery"
        try:
            response = requests.delete(url, headers=headers, verify=False)
            response.raise_for_status()
            logging.info(f'Delete all discovery tasks complete.')
            return
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            raise SystemExit()


    def add_discovery_node(self, node_info):
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = {
                'x-auth-token': self.token,
                'content-type': 'application/json'}
        mount_point = 'dna/intent/api/v1/discovery'
        url = "https://%s:%s/%s"%(self.dnac_ip, self.dnac_port, mount_point)
        payload = { "cdpLevel": 1,
                    "lldpLevel": 1,
                    "discoveryType": "SINGLE",
                    "protocolOrder": "ssh,telnet", }
        for key, value in node_info.items():
            if 'List' in key and key != "ipAddressList":
                payload[key] = [value]
            else:
                payload[key] = value
        logging.info(f'Adding discovery task for: {node_info["ipAddressList"]}')
        logging.debug(f'Adding discovery task payload: {payload}')
        try:
            response = requests.post(url=url, headers=headers, data=json.dumps(payload), verify=False)
            response.raise_for_status()
            info = response.json()['response']
            logging.info(f'Adding discovery task done for: {node_info["ipAddressList"]}')
            logging.debug(f'Adding discovery ta: {info}')
            return info['taskId']
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            raise SystemExit()


    def get_siteid_by_name(self, site_name=None, site_id=None, site_type=None, 
                       offset=None, limit=None):
        """
        Get Site V2 - Get site(s) by site-name-hierarchy, siteId, or type.
        
        API to get site(s) by site-name-hierarchy or siteId or type. 
        List all sites if these parameters are not given as an input.
        
        Args:
            site_name (str): Site name hierarchy (E.g. Global/USA/CA)
            site_id (str): Site Id
            site_type (str): Site type (Acceptable values: area, building, floor)
            offset (int): Offset/starting index for pagination
            limit (int): Number of sites to be listed. Default and max supported value is 500
            
        Returns:
            str or list: Site ID if site_name is provided, otherwise list of sites
        """
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        
        headers = {
            'x-auth-token': self.token,
            'content-type': 'application/json'
        }
        
        # Build query parameters
        params = {}
        if site_name:
            params['groupNameHierarchy'] = site_name
        if site_id:
            params['id'] = site_id
        if site_type:
            params['type'] = site_type
        if offset is not None:
            params['offset'] = offset
        if limit is not None:
            params['limit'] = min(limit, 500)  # Max 500 per API spec
        
        url = f"https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v2/site"
        
        try:
            response = requests.get(url, headers=headers, params=params, verify=False)
            response.raise_for_status()
            result = response.json()
            
            # Handle response structure
            sites = result.get('response', [])
            
            if site_name:
                # Backward compatibility: return site ID when searching by name
                if sites and len(sites) > 0:
                    site_info = sites[0]
                    site_id_value = site_info.get('id')
                    logging.info(f'Got Site ID for: {site_name}')
                    logging.debug(f'Site info: {site_info}')
                    return site_id_value
                else:
                    logging.warning(f'No site found for: {site_name}')
                    return None
            else:
                # Return full list of sites when not searching by specific name
                logging.info(f'Got {len(sites)} site(s)')
                logging.debug(f'Sites: {sites}')
                return sites
                
        except requests.exceptions.HTTPError as err:
            if err.response is not None:
                status_code = err.response.status_code
                if status_code == 400:
                    logging.error(f'Bad request - invalid parameters: {err}')
                elif status_code == 401:
                    logging.error(f'Authentication failed: {err}')
                elif status_code == 404:
                    logging.error(f'Site not found: {err}')
                elif status_code == 406:
                    logging.error(f'Request not acceptable: {err}')
                else:
                    logging.error(f'HTTP error: {err}')
            else:
                logging.error(err, exc_info=True)
            return None
        except Exception as err:
            logging.error(f'Error getting site: {err}', exc_info=True)
            return None


    def get_count_discovery(self):
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = { 'x-auth-token': self.token,
                    'content-type': 'application/json' }
        url = f"https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/discovery/count"
        try:
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            info = response.json()['response']
            logging.info(f'Got count of all discovery jobs')
            return info
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            raise SystemExit()


    def get_all_discovery_jobs(self, num):
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        recordsToReturn = num
        headers = { 'x-auth-token': self.token,
                    'content-type': 'application/json' }
        url = f"https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/discovery/1/{recordsToReturn}"
        try:
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            info = response.json()['response']
            logging.info(f'Got count of all discovery jobs')
            return info
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            raise SystemExit()


    def update_existing_discovery_job(self, discoveryInfo, password):
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = { 'x-auth-token': self.token,
                    'content-type': 'application/json' }
        url = f"https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/discovery"
        discoveryInfo['discoveryStatus'] = 'active'
        discoveryInfo['discoveryCondition'] = 'Yet to Start'
        discoveryInfo['passwordList'] = password
        discoveryInfo['enablePasswordList'] = password
        discoveryInfo['snmpRoCommunity'] = password
        discoveryInfo['snmpRwCommunity'] = password
        try:
            response = requests.put(url, headers=headers, data=json.dumps(discoveryInfo), verify=False)
            response.raise_for_status()
            info = response.json()['response']
            logging.info(f'Update existing discovery job')
            return info
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            raise SystemExit()


    def assign_device_to_site(self, site_id, device_ip): #deprecated
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = { 'x-auth-token': self.token,
                    'content-type': 'application/json' }
        url = f"https://{self.dnac_ip}:{self.dnac_port}/dna/system/api/v1/site/{site_id}/device"
        payload = { 'device': [ { 'ip': device_ip } ] }
        try:
            response = requests.post(url, headers=headers, data=json.dumps(payload), verify=False)
            response.raise_for_status()
            info = response.json()
            executionStatusPath = info['executionStatusUrl']
            url = f"https://{self.dnac_ip}:{self.dnac_port}" + executionStatusPath
            while True:
                response = requests.get(url, headers=headers, verify=False)
                executionStatus = response.json()['status']
                if executionStatus == 'SUCCESS':
                    executionError = ''
                    logging.debug(f'{device_ip}-{site_id}-{executionStatusPath}: {executionStatus}, {executionError}')
                    break
                elif executionStatus == 'FAILURE':
                    executionError = response.json()['bapiError']
                    logging.debug(f'{device_ip}-{site_id}-{executionStatusPath}: {executionStatus}, {executionError}')
                    break
                else:
                    logging.debug(f'{device_ip}-{site_id}-{executionStatusPath}: {executionStatus}')
            return executionStatus, executionError
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            raise SystemExit()


    def unassign_device_from_site(self, device_ids):
        """
        Unassign network devices from sites.
        
        Unassign unprovisioned network devices from their site. If device controllability 
        is enabled, it will be triggered once device unassigned from site successfully.
        
        Args:
            device_ids (list): List of device IDs (UUIDs) to unassign from sites (required)
            
        Returns:
            dict: Response containing taskId and url, or None if error occurs
        """
        # Rate limiting check (50 requests per minute)
        current_time = time.time()
        time_elapsed = current_time - self._rate_limit_start_time
        
        # Reset counter every 60 seconds
        if time_elapsed >= 60:
            self._request_count = 0
            self._rate_limit_start_time = current_time
        
        # Check if we've hit the rate limit (50 requests per minute)
        if self._request_count >= 50:
            sleep_time = 60 - time_elapsed
            if sleep_time > 0:
                logging.info(f'Rate limit reached. Sleeping for {sleep_time:.2f} seconds...')
                time.sleep(sleep_time)
                self._request_count = 0
                self._rate_limit_start_time = time.time()
        
        # Ensure minimum interval between requests (1.2 seconds)
        time_since_last_request = current_time - self._last_request_time
        if time_since_last_request < 1.2:
            time.sleep(1.2 - time_since_last_request)
        
        self._request_count += 1
        self._last_request_time = time.time()
        
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        
        headers = {
            'x-auth-token': self.token,
            'Content-Type': 'application/json'
        }
        
        url = f'https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/networkDevices/unassignFromSite/apply'
        
        # Build payload with device IDs
        payload = {
            'deviceIds': device_ids
        }
        
        logging.info(f'Unassigning {len(device_ids)} device(s) from site')
        logging.debug(f'Payload: {payload}')
        
        try:
            response = requests.post(url, headers=headers, data=json.dumps(payload), verify=False)
            response.raise_for_status()
            result = response.json()
            
            logging.info(f'Unassign devices from site request submitted')
            logging.debug(f'Response: {result}')
            
            # Extract task information from response
            task_id = result.get('response', {}).get('taskId')
            task_url = result.get('response', {}).get('url')
            
            if task_id:
                logging.info(f'Unassign task created - TaskId: {task_id}')
                return {
                    'taskId': task_id,
                    'url': task_url,
                    'response': result.get('response')
                }
            else:
                logging.warning('No taskId in response')
                return result
            
        except requests.exceptions.HTTPError as err:
            if err.response is not None:
                status_code = err.response.status_code
                if status_code == 400:
                    logging.error(f'Bad request - invalid parameters: {err}')
                elif status_code == 401:
                    logging.error(f'Authentication failed: {err}')
                elif status_code == 403:
                    logging.error(f'Forbidden - insufficient permissions: {err}')
                elif status_code == 404:
                    logging.error(f'Resource not found: {err}')
                elif status_code == 409:
                    logging.error(f'Conflict - resource in conflicted state: {err}')
                elif status_code == 415:
                    logging.error(f'Unsupported media type: {err}')
                else:
                    logging.error(f'HTTP error: {err}')
            else:
                logging.error(err, exc_info=True)
            logging.debug(f'Response: {err.response.text if err.response else "No response"}')
            return None
        except Exception as err:
            logging.error(f'Error unassigning devices from site: {err}', exc_info=True)
            return None


    def assign_devices_to_site(self, site_id, device_ids):
        """
        Assign network devices to a site.
        
        Assign unprovisioned network devices to a site. Can also be used to assign 
        unprovisioned network devices to a different site. If device controllability 
        is enabled, it will be triggered once device assigned to site successfully.
        
        Args:
            site_id (str): Site ID (UUID) where devices should be assigned (required)
            device_ids (list): List of device IDs (UUIDs) to assign to the site (required, max 100)
            
        Returns:
            dict: Response containing taskId and url, or None if error occurs
        """
        # Validate device_ids list length (max 100 devices per API limitation)
        if not device_ids:
            logging.error('device_ids list is empty')
            return None
        
        if len(device_ids) > 100:
            logging.error(f'device_ids list exceeds maximum limit: {len(device_ids)} devices (max 100)')
            return None
        
        # Rate limiting check (50 requests per minute)
        current_time = time.time()
        time_elapsed = current_time - self._rate_limit_start_time
        
        # Reset counter every 60 seconds
        if time_elapsed >= 60:
            self._request_count = 0
            self._rate_limit_start_time = current_time
        
        # Check if we've hit the rate limit (50 requests per minute)
        if self._request_count >= 50:
            sleep_time = 60 - time_elapsed
            if sleep_time > 0:
                logging.info(f'Rate limit reached. Sleeping for {sleep_time:.2f} seconds...')
                time.sleep(sleep_time)
                self._request_count = 0
                self._rate_limit_start_time = time.time()
        
        # Ensure minimum interval between requests (1.2 seconds)
        time_since_last_request = current_time - self._last_request_time
        if time_since_last_request < 1.2:
            time.sleep(1.2 - time_since_last_request)
        
        self._request_count += 1
        self._last_request_time = time.time()
        
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        
        headers = {
            'x-auth-token': self.token,
            'Content-Type': 'application/json'
        }
        
        url = f'https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/networkDevices/assignToSite/apply'
        
        # Build payload with site ID and device IDs
        payload = {
            'siteId': site_id,
            'deviceIds': device_ids
        }
        
        logging.info(f'Assigning {len(device_ids)} device(s) to site: {site_id}')
        logging.debug(f'Payload: {payload}')
        
        try:
            response = requests.post(url, headers=headers, data=json.dumps(payload), verify=False)
            response.raise_for_status()
            result = response.json()
            
            logging.info(f'Assign devices to site request submitted')
            logging.debug(f'Response: {result}')
            
            # Extract task information from response
            task_id = result.get('response', {}).get('taskId')
            task_url = result.get('response', {}).get('url')
            
            if task_id:
                logging.info(f'Assign task created - TaskId: {task_id}')
                return {
                    'taskId': task_id,
                    'url': task_url,
                    'response': result.get('response')
                }
            else:
                logging.warning('No taskId in response')
                return result
            
        except requests.exceptions.HTTPError as err:
            if err.response is not None:
                status_code = err.response.status_code
                if status_code == 400:
                    logging.error(f'Bad request - invalid parameters: {err}')
                elif status_code == 401:
                    logging.error(f'Authentication failed: {err}')
                elif status_code == 403:
                    logging.error(f'Forbidden - insufficient permissions: {err}')
                elif status_code == 404:
                    logging.error(f'Resource not found: {err}')
                elif status_code == 409:
                    logging.error(f'Conflict - resource in conflicted state: {err}')
                elif status_code == 415:
                    logging.error(f'Unsupported media type: {err}')
                else:
                    logging.error(f'HTTP error: {err}')
            else:
                logging.error(err, exc_info=True)
            logging.debug(f'Response: {err.response.text if err.response else "No response"}')
            return None
        except Exception as err:
            logging.error(f'Error assigning devices to site: {err}', exc_info=True)
            return None


    def edit_access_points_positions(self, floor_id, positions_data):
        """
        Edit the Access Points Positions - Position or reposition the Access Points on the map.
        
        Bulk update access point positions on a specific floor. This API allows you to
        position or reposition multiple access points on the floor map.
        
        Args:
            floor_id (str): Floor Id (required)
            positions_data (list): List of access point position data (required)
                Each item should contain:
                - id (str): Access Point ID
                - position (dict): Position data with x, y, z coordinates
                - radios (list): Optional radio configuration data
                And any other required fields per API schema
            
        Returns:
            dict: Response containing taskId and url, or result data, None if error occurs
        """
        # Rate limiting check (50 requests per minute per API spec)
        current_time = time.time()
        time_elapsed = current_time - self._rate_limit_start_time
        
        # Reset counter every 60 seconds
        if time_elapsed >= 60:
            self._request_count = 0
            self._rate_limit_start_time = current_time
        
        # Check if we've hit the rate limit (50 requests per minute)
        if self._request_count >= 50:
            sleep_time = 60 - time_elapsed
            if sleep_time > 0:
                logging.info(f'Rate limit reached. Sleeping for {sleep_time:.2f} seconds...')
                time.sleep(sleep_time)
                self._request_count = 0
                self._rate_limit_start_time = time.time()
        
        # Ensure minimum interval between requests (1.2 seconds)
        time_since_last_request = current_time - self._last_request_time
        if time_since_last_request < 1.2:
            time.sleep(1.2 - time_since_last_request)
        
        self._request_count += 1
        self._last_request_time = time.time()
        
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        
        headers = {
            'x-auth-token': self.token,
            'Content-Type': 'application/json'
        }
        
        url = f'https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v2/floors/{floor_id}/accessPointPositions/bulkChange'
        
        # Build payload - API expects list directly without wrapper
        payload = positions_data
        
        logging.info(f'Editing access point positions for floor: {floor_id}')
        logging.debug(f'Payload: {payload}')
        
        try:
            response = requests.post(url, headers=headers, data=json.dumps(payload), verify=False)
            response.raise_for_status()
            result = response.json()
            
            logging.info(f'Edit access points positions request submitted for floor: {floor_id}')
            logging.debug(f'Response: {result}')
            
            # Extract task information if available
            task_id = result.get('response', {}).get('taskId') if isinstance(result.get('response'), dict) else None
            task_url = result.get('response', {}).get('url') if isinstance(result.get('response'), dict) else None
            
            if task_id:
                logging.info(f'Edit positions task created - TaskId: {task_id}')
                return {
                    'taskId': task_id,
                    'url': task_url,
                    'response': result.get('response')
                }
            else:
                logging.info('Edit positions request completed')
                return result
            
        except requests.exceptions.HTTPError as err:
            if err.response is not None:
                status_code = err.response.status_code
                if status_code == 202:
                    logging.info(f'Request accepted: {err}')
                    return err.response.json() if err.response.text else {'status': 'accepted'}
                elif status_code == 204:
                    logging.info(f'Request successful - no content returned')
                    return {'status': 'success', 'message': 'No content'}
                elif status_code == 206:
                    logging.info(f'Partial content returned')
                    return err.response.json() if err.response.text else {'status': 'partial_content'}
                elif status_code == 400:
                    logging.error(f'Bad request - invalid parameters: {err}')
                elif status_code == 401:
                    logging.error(f'Authentication failed: {err}')
                elif status_code == 403:
                    logging.error(f'Forbidden - insufficient permissions: {err}')
                elif status_code == 404:
                    logging.error(f'Floor not found: {floor_id}')
                elif status_code == 409:
                    logging.error(f'Conflict - resource in conflicted state: {err}')
                elif status_code == 415:
                    logging.error(f'Unsupported media type: {err}')
                elif status_code == 500:
                    logging.error(f'Server error: {err}')
                elif status_code == 501:
                    logging.error(f'Not implemented: {err}')
                elif status_code == 502:
                    logging.error(f'Bad gateway: {err}')
                elif status_code == 503:
                    logging.error(f'Service temporarily unavailable: {err}')
                elif status_code == 504:
                    logging.error(f'Gateway timeout: {err}')
                else:
                    logging.error(f'HTTP error: {err}')
            else:
                logging.error(err, exc_info=True)
            logging.debug(f'Response: {err.response.text if err.response else "No response"}')
            return None
        except Exception as err:
            logging.error(f'Error editing access point positions: {err}', exc_info=True)
            return None


    def get_access_points_positions(self, floor_id, name=None, mac_address=None, 
                                    ap_type=None, model=None, offset=None, limit=None):
        """
        Get Access Points positions assigned for a specific floor.
        
        Retrieve all Access Points positions assigned for a specific floor. Can filter by
        AP name, MAC address, type, or model.
        
        Args:
            floor_id (str): Floor Id (required)
            name (str): Access Point name filter (optional)
            mac_address (str): Access Point MAC address filter (optional)
            ap_type (str): Access Point type filter (optional)
            model (str): Access Point model filter (optional)
            offset (int): Starting record index (1-based, minimum 1) (optional)
            limit (int): Number of records to return (min 1, max 500) (optional)
            
        Returns:
            list or dict: List of access point positions or response dict, None if error occurs
        """
        # Rate limiting check (100 requests per minute per API spec)
        current_time = time.time()
        time_elapsed = current_time - self._rate_limit_start_time
        
        # Reset counter every 60 seconds
        if time_elapsed >= 60:
            self._request_count = 0
            self._rate_limit_start_time = current_time
        
        # Check if we've hit the rate limit (100 requests per minute for this API)
        if self._request_count >= 100:
            sleep_time = 60 - time_elapsed
            if sleep_time > 0:
                logging.info(f'Rate limit reached. Sleeping for {sleep_time:.2f} seconds...')
                time.sleep(sleep_time)
                self._request_count = 0
                self._rate_limit_start_time = time.time()
        
        # Ensure minimum interval between requests (0.6 seconds for 100/min)
        time_since_last_request = current_time - self._last_request_time
        if time_since_last_request < 0.6:
            time.sleep(0.6 - time_since_last_request)
        
        self._request_count += 1
        self._last_request_time = time.time()
        
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        
        headers = {
            'x-auth-token': self.token,
            'content-type': 'application/json'
        }
        
        # Build query parameters
        params = {}
        if name:
            params['name'] = name
        if mac_address:
            params['macAddress'] = mac_address
        if ap_type:
            params['type'] = ap_type
        if model:
            params['model'] = model
        if offset is not None:
            params['offset'] = max(offset, 1)  # Minimum 1
        if limit is not None:
            params['limit'] = min(max(limit, 1), 500)  # Min 1, Max 500
        
        url = f'https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v2/floors/{floor_id}/accessPointPositions'
        
        logging.info(f'Getting access point positions for floor: {floor_id}')
        logging.debug(f'Query parameters: {params}')
        
        try:
            response = requests.get(url, headers=headers, params=params, verify=False)
            response.raise_for_status()
            result = response.json()
            
            logging.info(f'Got access point positions for floor: {floor_id}')
            logging.debug(f'Response: {result}')
            
            # Return the response data
            return result.get('response', result)
            
        except requests.exceptions.HTTPError as err:
            if err.response is not None:
                status_code = err.response.status_code
                if status_code == 204:
                    logging.info(f'No content returned for floor: {floor_id}')
                    return []
                elif status_code == 206:
                    logging.info(f'Partial content returned for floor: {floor_id}')
                    # Try to return partial content if available
                    try:
                        return err.response.json().get('response', [])
                    except:
                        return []
                elif status_code == 400:
                    logging.error(f'Bad request - invalid parameters: {err}')
                elif status_code == 401:
                    logging.error(f'Authentication failed: {err}')
                elif status_code == 403:
                    logging.error(f'Forbidden - insufficient permissions: {err}')
                elif status_code == 404:
                    logging.error(f'Floor not found: {floor_id}')
                elif status_code == 406:
                    logging.error(f'Request not acceptable: {err}')
                elif status_code == 409:
                    logging.error(f'Conflict - resource in conflicted state: {err}')
                elif status_code == 415:
                    logging.error(f'Unsupported media type: {err}')
                elif status_code == 500:
                    logging.error(f'Server error: {err}')
                elif status_code == 501:
                    logging.error(f'Not implemented: {err}')
                elif status_code == 503:
                    logging.error(f'Service temporarily unavailable: {err}')
                elif status_code == 504:
                    logging.error(f'Gateway timeout: {err}')
                else:
                    logging.error(f'HTTP error: {err}')
            else:
                logging.error(err, exc_info=True)
            logging.debug(f'Response: {err.response.text if err.response else "No response"}')
            return None
        except Exception as err:
            logging.error(f'Error getting access point positions: {err}', exc_info=True)
            return None


    def get_template_id(self, tname):
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = {
                'x-auth-token': self.token,
                'content-type': 'application/json'}
        url = f"https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v2/template-programmer/template?name={tname}"
        try:
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            tid = response.json()['response'][0]['id']
            logging.info(f'Got Template Info for: {tname}')
            logging.info(f'Got Template ID: {tid}')
            logging.debug(f'Template Info: {response.json()["response"]}')
            return tid
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            raise SystemExit()


    def deploy_template_v2(self, tname, targetInfo):
        '''
        Sample targetInfo:
            'targetInfo':  [
                {
                    'id': 'hostname',
                    'params': {
                        'key': 'value'
                    },
                    'type': 'MANAGED_DEVICE_HOSTNAME',
                    "resourceParams": [
                        {
                            "type": "MANAGED_DEVICE_HOSTNAME",
                            "scope": "RUNTIME",
                            "value": "hostname"
                        }
                    ]
                }
            ]
        '''
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = {
                'x-auth-token': self.token,
                'content-type': 'application/json'}
        url = f"https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v2/template-programmer/template/deploy"
        tempid = self.get_template_id(tname)
        payload = {
            'forcePushTemplate': 'True',
            'isComposite': 'False',
            'targetInfo': targetInfo,
            'templateId': tempid
        }
        logging.debug(f'Template Payload: {payload}')
        try:
            response = requests.post(url, headers=headers, data=json.dumps(payload), verify=False)
            response.raise_for_status()
            info = response.json()['response']
            logging.debug(f'response={response.json()}')
            match response.status_code:
                case 202:
                    return True, response.json()['response']['taskId']
                case 400:
                    return False, response.json()['response']
                case _:
                    return False, response.json()['response']
        except Exception as err:
            logging.error(err, exc_info=True)
            raise SystemExit()


    def get_tdeployment_info(self, did):
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = {
                'x-auth-token': self.token,
                'content-type': 'application/json'}
        url = f"https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/template-programmer/template/deploy/status/{did}"
        try:
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            info = response.json()
            logging.info(f'Got Template Deployment Info for: {did}')
            logging.debug(f'Task Info: {info}')
            return info
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            raise SystemExit()

    
    def make_report_schedule(self, payload):
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = {
                'x-auth-token': self.token,
                'content-type': 'application/json'}
        url = f"https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/data/reports"
        payload = payload
        logging.debug(f'Report Payload: {payload}')
        try:
            response = requests.post(url, headers=headers, json=payload, verify=False)
            response.raise_for_status
            logging.debug(f'Create report response: {response.text}')
            reportId = response.json()['reportId']
            return reportId
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            raise SystemExit()


    def get_report_excecution_id(self, reportId):
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = {
                'x-auth-token': self.token,
                'content-type': 'application/json'}
        url = f"https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/data/reports/{reportId}"
        while True:
            try:
                response = requests.get(url, headers=headers, verify=False)
                response.raise_for_status()
                logging.debug(f'get_report_executionid response={response.json()}')
                if response.json()['reportWasExecuted']:
                    executionId = response.json()['executions'][0]['executionId']
                    logging.info(f'reportId={reportId}, executionId={executionId}')
                    return executionId
                else:
                    time.sleep(60)
            except requests.exceptions.HTTPError as err:
                logging.error(err, exc_info=True)
                raise SystemExit()

    
    def check_report_execution_status(self, reportId, executionId):
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = {
                'x-auth-token': self.token,
                'content-type': 'application/json'}
        url = f"https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/data/reports/{reportId}/executions"
        while True:
            try:
                r_error = []
                r_warn = []
                r_status = False
                response = requests.get(url, headers=headers, verify=False)
                response.raise_for_status()
                logging.debug(f'get_report_execution_status response={response.json()}')
                if executionId == response.json()['executions'][0]['executionId']:
                    processStatus = response.json()['executions'][0]['processStatus']
                    logging.info(f'reportId={reportId}, executionId={executionId}, processStatus={processStatus}')
                    if processStatus == 'SUCCESS':
                        r_status = True
                        if response.json()['executions'][0]['warnings']:
                            r_warn = response.json()['executions'][0]['warnings']
                        return r_status, r_warn, r_error
                    elif processStatus == 'IN_PROGRESS' or processStatus == None:
                        time.sleep(30)
                        continue
                    elif processStatus:
                        if response.json()['executions'][0]['warnings']:
                            r_warn = response.json()['executions'][0]['warnings']
                        if response.json()['executions'][0]['Errors']:
                            r_error = response.json()['executions'][0]['Errors']
                        return r_status, r_warn, r_error
                else:
                    time.sleep(30)
            except requests.exceptions.HTTPError as err:
                logging.error(err, exc_info=True)
                raise SystemExit()

    
    def download_report(self, reportId, executionId):
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = {
                'x-auth-token': self.token,
                'content-type': 'application/json'}
        url = f"https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/data/reports/{reportId}/executions/{executionId}"
        try:
            response = requests.get(url, headers=headers, verify=False, stream=True)
            response.raise_for_status()
            report = response.json()
            logging.info(f'reportId={reportId}, get report complete')
            logging.debug(f'get_report response={response.json()}')
            return report
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            raise SystemExit()

    
    def get_reportid_by_name(self, name):
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        report_id = None
        headers = {
                'x-auth-token': self.token,
                'content-type': 'application/json'}
        url = f"https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/data/reports"
        try:
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            rlist = response.json()
            logging.info(f'Get report list')
            logging.debug(f'rlist={rlist}')
            for rp in rlist:
                if rp['name'] == name:
                    report_id = rp['reportId']
            return report_id
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            raise SystemExit()
        except Exception as err:
            logging.error(err, exc_info=True)
            raise SystemExit()


    def delete_report(self, reportId):
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = {
                'x-auth-token': self.token,
                'content-type': 'application/json'}
        url = f"https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/data/reports/{reportId}"
        try:
            response = requests.delete(url, headers=headers, verify=False)
            response.raise_for_status()
            logging.debug(f'delete_report response={response.json()}')
            logging.info(f'delete report, reportId={reportId}')
            return
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            raise SystemExit()


    def get_backup_info(self):
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = {
                'x-auth-token': self.token,
                'content-type': 'application/json'}
        url = f"https://{self.dnac_ip}:{self.dnac_port}/api/system/v1/maglev/backup"
        bkp_info = []
        try:
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            logging.debug(f'get_backup_info response={response.json()}')
            for bkp in response.json()['response']:
                bkp_item = {
                                'backup_id': bkp['backup_id'],
                                'status': bkp['status'],
                                'start_timestamp': bkp['start_timestamp'],
                                'end_timestamp': bkp['end_timestamp']
                            }
                bkp_info.append(bkp_item)
            logging.debug(f'backup_info: {bkp_info}')
            return bkp_info
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            return bkp_info
        except Exception as err:
            logging.error(err, exc_info=True)
            raise SystemExit()

    def delete_backup(self, backupId):
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = {
                'x-auth-token': self.token,
                'content-type': 'application/json'}
        url = f"https://{self.dnac_ip}:{self.dnac_port}/api/system/v1/maglev/backup/{backupId}"
        try:
            response = requests.delete(url, headers=headers, verify=False)
            response.raise_for_status()
            logging.debug(f'delete_backup response={response.json()}')
            logging.info(f'delete backup, backupId={backupId}')
            return
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            raise SystemExit()


    def get_ap_config(self, apEthMac):
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = {
                'x-auth-token': self.token,
                'content-type': 'application/json'}
        url = f"https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/wireless/access-point-configuration?key={apEthMac}"
        try:
            ap_config = {}
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            logging.debug(f'{apEthMac} ap_config response={response.json()}')
            if response.json:
                logging.info(f'{apEthMac} ap_config received')
            else:
                logging.info(f'{apEthMac} ap_config None')
            return ap_config
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            raise SystemExit()


    def change_ap_name_and_loc(self, updateApInfo):
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = {
                'x-auth-token': self.token,
                'content-type': 'application/json'}
        url = f'https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/wireless/access-point-configuration'
        payload = updateApInfo
        logging.debug(f'updateApInfo payload: {payload}')
        try:
            response = requests.post(url, headers=headers, json=payload, verify=False)
            response.raise_for_status()
            logging.debug(f'ap provisioning response: {response.json()}')
            taskId = response.json()['response']['taskId']
            logging.info(f'taskId: {taskId}')
            return taskId
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            raise SystemExit()
        except Exception as err:
            logging.error(err, exc_info=True)
            raise SystemExit()


    def get_ap_config_task_info(self, tid):
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = {
                'x-auth-token': self.token,
                'content-type': 'application/json'}
        url = f'https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/wireless/access-point-configuration/task/{tid}'
        try:
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            info = response.json()
            logging.info(f'Got Task Info for: {tid}')
            logging.debug(f'Task Info: {info}')
            return info
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            raise SystemExit()
        except Exception as err:
            logging.error(err, exc_info=True)
            raise SystemExit()


    def get_device_list(self, hostname=None, managementIpAddress=None, macAddress=None,
                        locationName=None, serialNumber=None, location=None, family=None,
                        device_type=None, series=None, collectionStatus=None, collectionInterval=None,
                        notSyncedForMinutes=None, errorCode=None, errorDescription=None,
                        softwareVersion=None, softwareType=None, platformId=None, role=None,
                        reachabilityStatus=None, upTime=None, associatedWlcIp=None,
                        license_name=None, license_type=None, license_status=None,
                        module_name=None, module_equipmenttype=None, module_servicestate=None,
                        module_vendorequipmenttype=None, module_partnumber=None,
                        module_operationstatecode=None, device_id=None, deviceSupportLevel=None,
                        offset=None, limit=None):
        """
        Get network device list based on filter criteria.
        
        Returns list of network devices based on filter criteria such as management IP address, 
        mac address, hostname, etc. Supports wildcard search using .* in any value.
        
        Args:
            hostname: Hostname filter (array/list of strings)
            managementIpAddress: Management IP address filter (array/list of strings)
            macAddress: MAC address filter (array/list of strings)
            locationName: Location name filter (array/list of strings)
            serialNumber: Serial number filter (array/list of strings)
            location: Location filter (array/list of strings)
            family: Device family filter (array/list of strings)
            device_type: Device type filter (array/list of strings)
            series: Device series filter (array/list of strings)
            collectionStatus: Collection status filter (array/list of strings)
            collectionInterval: Collection interval filter (array/list of strings)
            notSyncedForMinutes: Not synced for minutes filter (array/list of strings)
            errorCode: Error code filter (array/list of strings)
            errorDescription: Error description filter (array/list of strings)
            softwareVersion: Software version filter (array/list of strings)
            softwareType: Software type filter (array/list of strings)
            platformId: Platform ID filter (array/list of strings)
            role: Device role filter (array/list of strings)
            reachabilityStatus: Reachability status filter (array/list of strings)
            upTime: Uptime filter (array/list of strings)
            associatedWlcIp: Associated WLC IP filter (array/list of strings)
            license_name: License name filter (array/list of strings)
            license_type: License type filter (array/list of strings)
            license_status: License status filter (array/list of strings)
            module_name: Module name filter (array/list of strings)
            module_equipmenttype: Module equipment type filter (array/list of strings)
            module_servicestate: Module service state filter (array/list of strings)
            module_vendorequipmenttype: Module vendor equipment type filter (array/list of strings)
            module_partnumber: Module part number filter (array/list of strings)
            module_operationstatecode: Module operation state code filter (array/list of strings)
            device_id: Comma separated device IDs (string). If provided, other filters are ignored.
            deviceSupportLevel: Device support level filter (string)
            offset: Starting index (1-based). Default: 1
            limit: Number of records per page. Min: 1, Max: 500. Default: 500
            
        Returns:
            List of network devices matching the filter criteria
        """
        # Rate limiting check
        current_time = time.time()
        time_elapsed = current_time - self._rate_limit_start_time
        
        # Reset counter every 60 seconds
        if time_elapsed >= 60:
            self._request_count = 0
            self._rate_limit_start_time = current_time
        
        # Check if we've hit the rate limit (50 requests per minute)
        if self._request_count >= 50:
            sleep_time = 60 - time_elapsed
            if sleep_time > 0:
                logging.info(f'Rate limit reached. Sleeping for {sleep_time:.2f} seconds...')
                time.sleep(sleep_time)
                self._request_count = 0
                self._rate_limit_start_time = time.time()
        
        # Ensure minimum interval between requests (1.2 seconds)
        time_since_last_request = current_time - self._last_request_time
        if time_since_last_request < 1.2:
            time.sleep(1.2 - time_since_last_request)
        
        self._request_count += 1
        self._last_request_time = time.time()
        
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        
        headers = {
            'x-auth-token': self.token,
            'content-type': 'application/json'
        }
        
        # Build query parameters
        params = {}
        
        # Helper function to add array parameters
        def add_array_param(param_name, param_value):
            if param_value:
                if isinstance(param_value, list):
                    params[param_name] = param_value
                else:
                    params[param_name] = [param_value]
        
        # Add all filter parameters
        add_array_param('hostname', hostname)
        add_array_param('managementIpAddress', managementIpAddress)
        add_array_param('macAddress', macAddress)
        add_array_param('locationName', locationName)
        add_array_param('serialNumber', serialNumber)
        add_array_param('location', location)
        add_array_param('family', family)
        add_array_param('type', device_type)
        add_array_param('series', series)
        add_array_param('collectionStatus', collectionStatus)
        add_array_param('collectionInterval', collectionInterval)
        add_array_param('notSyncedForMinutes', notSyncedForMinutes)
        add_array_param('errorCode', errorCode)
        add_array_param('errorDescription', errorDescription)
        add_array_param('softwareVersion', softwareVersion)
        add_array_param('softwareType', softwareType)
        add_array_param('platformId', platformId)
        add_array_param('role', role)
        add_array_param('reachabilityStatus', reachabilityStatus)
        add_array_param('upTime', upTime)
        add_array_param('associatedWlcIp', associatedWlcIp)
        add_array_param('license.name', license_name)
        add_array_param('license.type', license_type)
        add_array_param('license.status', license_status)
        add_array_param('module+name', module_name)
        add_array_param('module+equpimenttype', module_equipmenttype)
        add_array_param('module+servicestate', module_servicestate)
        add_array_param('module+vendorequipmenttype', module_vendorequipmenttype)
        add_array_param('module+partnumber', module_partnumber)
        add_array_param('module+operationstatecode', module_operationstatecode)
        
        # Add string parameters
        if device_id:
            params['id'] = device_id
        if deviceSupportLevel:
            params['deviceSupportLevel'] = deviceSupportLevel
        
        # Add pagination parameters
        if offset is not None:
            params['offset'] = offset
        if limit is not None:
            params['limit'] = min(limit, 500)  # Max 500 per API spec
        
        url = f'https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/network-device'
        
        try:
            response = requests.get(url, headers=headers, params=params, verify=False)
            response.raise_for_status()
            result = response.json()
            
            logging.info(f'Got device list')
            logging.debug(f'Device list response: {result}')
            
            return result.get('response', [])
            
        except requests.exceptions.HTTPError as err:
            logging.error(f'HTTP error getting device list: {err}')
            logging.debug(f'Response: {err.response.text if err.response else "No response"}')
            return None
        except Exception as err:
            logging.error(f'Error getting device list: {err}', exc_info=True)
            return None


    def get_interface_by_ip(self, ipAddress):
        intf_info = {}
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = {
                'x-auth-token': self.token,
                'content-type': 'application/json'}
        url = f'https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/interface/ip-address/{ipAddress}'
        try:
            response = requests.get(url, headers=headers, verify=False)
            logging.debug(f'response={response.text}')
            intf_info = response.json()
            if response.status_code == 404:
                portName = intf_info['response']['errorCode']
                logging.debug(f'portName={portName}')
                return portName
            elif response.status_code == 200:
                portName = intf_info['response'][0]['portName']
                logging.debug(f'portName={portName}')
                return portName
            else:
                response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            raise SystemExit()
        except Exception as err:
            logging.error(err, exc_info=True)
            raise SystemExit()


    def delete_device_by_id(self, did):
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = {
                'x-auth-token': self.token,
                'content-type': 'application/json'}
        url = f'https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/network-device/{did}'
        try:
            response = requests.delete(url, headers=headers, verify=False)
            response.raise_for_status()
            logging.debug(f'response={response.json()}')
            taskId = response.json()['response']['taskId']
            logging.info(f'taskId: {taskId}')
            return taskId
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            raise SystemExit()
        except Exception as err:
            logging.error(err, exc_info=True)
            raise SystemExit()


    def run_command_runner(self, commands_list, deviceUuids_list, name=None, 
                          description=None, timeout=None):
        """
        Run read-only commands on devices to get their real-time configuration
        Includes rate limiting to prevent 429 errors (stay under 100 API calls per minute)
        
        Args:
            commands_list (list): List of CLI commands to execute (read-only)
            deviceUuids_list (list): List of device UUIDs to run commands on
            name (str): Optional name for the command request (e.g., 'getshowrun', 'deviceinterfacestatusCli')
            description (str): Optional description about the command request
            timeout (int): Optional timeout in seconds (default: 300 seconds if not provided)
        
        Returns:
            dict: Response containing taskId and url for tracking command execution
        """
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        
        headers = {
            'x-auth-token': self.token,
            'Content-Type': 'application/json'
        }
        
        # Build payload with required and optional parameters
        payload = {
            'commands': commands_list,
            'deviceUuids': deviceUuids_list
        }
        
        # Add optional parameters if provided
        if name:
            payload['name'] = name
        if description:
            payload['description'] = description
        if timeout:
            payload['timeout'] = timeout
        
        url = f'https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/network-device-poller/cli/read-request'
        response = None
        
        try:
            # Rate limiting: Ensure we don't exceed 50 requests per minute to avoid 429 errors
            current_time = time.time()
            
            # Reset counter every minute
            if current_time - self._rate_limit_start_time >= 60:
                self._request_count = 0
                self._rate_limit_start_time = current_time
            
            # If we've made 50 requests in the current minute, wait
            if self._request_count >= 50:
                sleep_time = 60 - (current_time - self._rate_limit_start_time) + 1
                logging.info(f'Rate limit reached (50 requests/minute). Sleeping for {sleep_time:.1f} seconds...')
                time.sleep(sleep_time)
                # Reset counter after waiting
                self._request_count = 0
                self._rate_limit_start_time = time.time()
            
            # Ensure minimum interval between requests (1.2 seconds = 50 requests/minute)
            time_since_last = current_time - self._last_request_time
            if time_since_last < 1.2:
                sleep_time = 1.2 - time_since_last
                logging.debug(f'Rate limiting: sleeping for {sleep_time:.2f} seconds')
                time.sleep(sleep_time)
            
            # Update tracking variables
            self._last_request_time = time.time()
            self._request_count += 1
            
            logging.info(f'Running command runner on {len(deviceUuids_list)} device(s) (Request #{self._request_count})')
            logging.debug(f'Commands: {commands_list}')
            logging.debug(f'Payload: {payload}')
            
            response = requests.post(url, headers=headers, data=json.dumps(payload), verify=False)
            response.raise_for_status()
            
            result = response.json()
            logging.debug(f'Response: {result}')
            
            task_id = result.get('response', {}).get('taskId')
            task_url = result.get('response', {}).get('url')
            
            if task_id:
                logging.info(f'Command runner task created - TaskId: {task_id}')
                if task_url:
                    logging.info(f'Task URL: {task_url}')
                
                # Return full response for flexibility
                return {
                    'taskId': task_id,
                    'url': task_url,
                    'version': result.get('version'),
                    'response': result.get('response')
                }
            else:
                logging.error('No taskId in response')
                return None
                
        except requests.exceptions.HTTPError as err:
            logging.error(f'HTTP Error running command runner: {err}', exc_info=True)
            if response is not None:
                try:
                    logging.error(f'Response: {response.text}')
                except:
                    logging.error('Response details unavailable')
            return None
        except Exception as err:
            logging.error(f'Unexpected error running command runner: {err}', exc_info=True)
            return None


    def get_config_by_id(self, did):
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = {
                'x-auth-token': self.token,
                'content-type': 'application/json'
                }
        url = f'https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/network-device/{did}/config'
        try:
            response = requests.get(url, headers=headers, verify=False)
            logging.debug(f'response.status_code={response.status_code}')
            logging.debug(f'response={response.json()}')
            match response.status_code:
                case 200:
                    return response.json()['response']
                case 400:
                    return ''
                case _:
                    return ''
        except Exception as err:
            logging.error(err, exc_info=True)
            raise SystemExit()
        

    def get_device_detail(self, identifier, searchBy, timestamp=None):
        """
        Get Device Detail - Returns detailed Network Device information.
        
        Returns detailed Network Device information retrieved by Mac Address, Device Name 
        or UUID for any given point of time.
        
        Args:
            identifier (str): One of "macAddress", "nwDeviceName", "uuid" (case insensitive) (required)
            searchBy (str): MAC Address, device name, or UUID of the network device (required)
            timestamp (int): UTC timestamp of device data in milliseconds (optional)
            
        Returns:
            dict: Device detail information or None if error occurs
        """
        # Rate limiting check
        current_time = time.time()
        time_elapsed = current_time - self._rate_limit_start_time
        
        # Reset counter every 60 seconds
        if time_elapsed >= 60:
            self._request_count = 0
            self._rate_limit_start_time = current_time
        
        # Check if we've hit the rate limit (50 requests per minute)
        if self._request_count >= 50:
            sleep_time = 60 - time_elapsed
            if sleep_time > 0:
                logging.info(f'Rate limit reached. Sleeping for {sleep_time:.2f} seconds...')
                time.sleep(sleep_time)
                self._request_count = 0
                self._rate_limit_start_time = time.time()
        
        # Ensure minimum interval between requests (1.2 seconds)
        time_since_last_request = current_time - self._last_request_time
        if time_since_last_request < 1.2:
            time.sleep(1.2 - time_since_last_request)
        
        self._request_count += 1
        self._last_request_time = time.time()
        
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        
        headers = {
            'x-auth-token': self.token,
            'content-type': 'application/json'
        }
        
        # Build query parameters
        params = {
            'identifier': identifier,
            'searchBy': searchBy
        }
        
        if timestamp is not None:
            params['timestamp'] = timestamp
        
        url = f'https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/device-detail'
        
        try:
            response = requests.get(url, headers=headers, params=params, verify=False)
            response.raise_for_status()
            result = response.json()
            
            logging.info(f'Got device detail for {identifier}={searchBy}')
            logging.debug(f'Device detail response: {result}')
            
            return result.get('response')
            
        except requests.exceptions.HTTPError as err:
            if err.response is not None:
                status_code = err.response.status_code
                if status_code == 400:
                    logging.error(f'Bad request - invalid parameters: {err}')
                elif status_code == 401:
                    logging.error(f'Authentication failed: {err}')
                elif status_code == 403:
                    logging.error(f'Forbidden - insufficient permissions: {err}')
                elif status_code == 404:
                    logging.error(f'Device not found: {err}')
                else:
                    logging.error(f'HTTP error: {err}')
            else:
                logging.error(err, exc_info=True)
            logging.debug(f'Response: {err.response.text if err.response else "No response"}')
            return None
        except Exception as err:
            logging.error(f'Error getting device detail: {err}', exc_info=True)
            return None


    def download_file_by_id(self, fileId):
        """
        Download a file specified by fileId.
        
        Downloads a file from DNA Center using the file identification number.
        
        Args:
            fileId (str): File Identification number (required)
            
        Returns:
            Response object: File content or None if error occurs
        """
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        
        headers = {
            'x-auth-token': self.token,
            'content-type': 'application/json'
        }
        
        url = f'https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/file/{fileId}'
        
        try:
            response = requests.get(url, headers=headers, verify=False, stream=True)
            response.raise_for_status()
            
            logging.info(f'Successfully downloaded file with ID: {fileId}')
            logging.debug(f'Response status code: {response.status_code}')
            logging.debug(f'Response json: {response.json()}')
            
            # Return the response object to allow caller to handle different content types
            return response.json() if 'application/json' in response.headers.get('Content-Type', '') else response.content
            
        except requests.exceptions.HTTPError as err:
            if err.response is not None and err.response.status_code == 404:
                logging.warning(f'File not found with ID: {fileId}')
            else:
                logging.error(f'HTTP error downloading file {fileId}: {err}', exc_info=True)
            return None
        except Exception as err:
            logging.error(f'Error downloading file {fileId}: {err}', exc_info=True)
            return None


    def run_command_runner_workflow(self, commands_list, deviceUuids_list, name=None, 
                                     description=None, timeout=None, poll_interval=5, 
                                     max_wait_time=300):
        """
        Complete workflow to run commands on devices and retrieve results.
        
        This function orchestrates the entire command runner workflow:
        1. Execute commands on specified devices using run_command_runner
        2. Poll task status every poll_interval seconds until completion
        3. Get task details to extract the file ID
        4. Download the file containing command results
        
        Args:
            commands_list (list): List of CLI commands to execute (read-only)
            deviceUuids_list (list): List of device UUIDs to run commands on
            name (str): Optional name for the command request
            description (str): Optional description about the command request
            timeout (int): Optional timeout in seconds for command execution (default: 300)
            poll_interval (int): Seconds to wait between status checks (default: 5)
            max_wait_time (int): Maximum time to wait for task completion in seconds (default: 300)
        
        Returns:
            dict: Dictionary containing:
                - success (bool): Whether the workflow completed successfully
                - task_id (str): The task ID from command runner
                - file_id (str): The file ID containing results (if successful)
                - file_data (bytes or dict): Raw file data - bytes if binary, dict if JSON (if successful)
                - file_data_json (dict or None): Parsed JSON data if file contains JSON, None otherwise
                - error (str): Error message (if failed)
        """
        result = {
            'success': False,
            'task_id': None,
            'file_id': None,
            'file_data': None,
            'file_data_json': None,
            'error': None
        }
        
        # Step 1: Run command runner
        logging.info('Step 1: Running command runner...')
        cmd_response = self.run_command_runner(
            commands_list=commands_list,
            deviceUuids_list=deviceUuids_list,
            name=name,
            description=description,
            timeout=timeout
        )
        
        if not cmd_response or 'taskId' not in cmd_response:
            result['error'] = 'Failed to execute command runner or no taskId returned'
            logging.error(result['error'])
            return result
        
        task_id = cmd_response['taskId']
        result['task_id'] = task_id
        logging.info(f'Command runner task created: {task_id}')
        
        # Step 2: Poll task status until completion
        logging.info(f'Step 2: Polling task status (interval: {poll_interval}s, max wait: {max_wait_time}s)...')
        start_time = time.time()
        task_status = None
        
        while time.time() - start_time < max_wait_time:
            # Get task status
            task_info = self.get_tasks_by_id(task_id)
            
            if not task_info:
                logging.warning(f'Could not retrieve task info for {task_id}, retrying...')
                time.sleep(poll_interval)
                continue
            
            task_status = task_info.get('status', '').upper()
            logging.info(f'Task status: {task_status}')
            
            if task_status == 'SUCCESS':
                logging.info('Task completed successfully!')
                break
            elif task_status == 'FAILURE':
                result['error'] = f'Task failed with status: {task_status}'
                logging.error(result['error'])
                return result
            else:
                # Task still in progress
                elapsed = time.time() - start_time
                logging.debug(f'Task in progress... (elapsed: {elapsed:.1f}s)')
                time.sleep(poll_interval)
        
        # Check if we timed out
        if task_status != 'SUCCESS':
            result['error'] = f'Task did not complete within {max_wait_time} seconds. Last status: {task_status}'
            logging.error(result['error'])
            return result
        
        # Step 3: Get task details to extract file ID
        logging.info('Step 3: Getting task details to extract file ID...')
        task_detail = self.get_task_detail_by_id(task_id)
        
        if not task_detail:
            result['error'] = 'Failed to retrieve task details'
            logging.error(result['error'])
            return result
        
        # Parse the progress field to get file ID
        progress = task_detail.get('progress', '')
        
        if not progress:
            result['error'] = 'No progress data in task details'
            logging.error(result['error'])
            return result
        
        try:
            # Progress is a JSON string like: {"fileId":"c80884af-b6e4-43a4-abca-41fe00aa8394"}
            progress_data = json.loads(progress)
            file_id = progress_data.get('fileId')
            
            if not file_id:
                result['error'] = 'No fileId found in progress data'
                logging.error(result['error'])
                return result
            
            result['file_id'] = file_id
            logging.info(f'File ID extracted: {file_id}')
            
        except json.JSONDecodeError as err:
            result['error'] = f'Failed to parse progress JSON: {err}'
            logging.error(result['error'])
            return result
        
        # Step 4: Download the file
        logging.info(f'Step 4: Downloading file {file_id}...')
        download_response = self.download_file_by_id(file_id)

        if download_response is None:
            result['error'] = 'Failed to download file'
            logging.error(result['error'])
            return result

        logging.debug(f'download_response: {download_response}')
        # Better solution with error handling
        if isinstance(download_response, bytes):
            try:
                # Decode binary to string, then parse JSON
                json_string = download_response.decode('utf-8')
                download_response_json = json.loads(json_string)
            except UnicodeDecodeError as e:
                logging.error(f'Failed to decode binary data: {e}')
                result['error'] = f'Failed to decode binary data: {e}'
                return result
            except json.JSONDecodeError as e:
                logging.error(f'Failed to parse JSON: {e}')
                result['error'] = f'Failed to parse JSON: {e}'
                return result
        elif isinstance(download_response, (dict, list)):
            # Already parsed as JSON
            download_response_json = download_response
        else:
            # Unknown type
            logging.error(f'Unexpected download_response type: {type(download_response)}')
            result['error'] = f'Unexpected response type: {type(download_response)}'
            return result
        logging.debug(f'download_response_json: {download_response_json}')
        result['file_data_json'] = download_response_json
        result['file_data'] = download_response
        result['success'] = True
        return result
        
        
    def sync_device(self, device_id_list):
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = {
                'x-auth-token': self.token,
                'content-type': 'application/json'}
        url = f'https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/network-device/sync'
        try:
            response = requests.put(url, headers=headers, json=device_id_list, verify=False)
            response.raise_for_status()
            logging.debug(f'response={response.json()}')
            return response.json()
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            raise SystemExit()
        except Exception as err:
            logging.error(err, exc_info=True)
            raise SystemExit()


    def get_task_tree(self, task_id): #sunset
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = {
                'x-auth-token': self.token,
                'content-type': 'application/json'}
        url = f'https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/task/{task_id}/tree'
        try:
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            logging.debug(f'response={response.json()}')
            return response.json()
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            raise SystemExit()
        except Exception as err:
            logging.error(err, exc_info=True)
            raise SystemExit()


    def get_device_enrich_detail(self, **kwargs):
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        headers = {
                'x-auth-token': self.token,
                'content-type': 'application/json'}
        for key, value in kwargs.items():
            headers[key] = value
        url = f'https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v1/device-enrichment-details'
        try:
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            logging.debug(f'response={response.json()}')
            return response.json()[0]['deviceDetails']
        except requests.exceptions.HTTPError as err:
            logging.error(err, exc_info=True)
            raise SystemExit()
        except Exception as err:
            logging.error(err, exc_info=True)
            raise SystemExit()

    def get_wireless_hosts(self, start_time=None, end_time=None, limit=500, offset=1,
                           attributes=None, filters=None, sort_by=None, order='asc'):
        """
        Get wireless hosts using the new Catalyst Center clients API with paging support
        Includes rate limiting to prevent 429 errors (stay under 100 API calls per minute)

        Args:
            start_time (int): Start time in UNIX epoch milliseconds (optional, defaults to 24 hours ago)
            end_time (int): End time in UNIX epoch milliseconds (optional, defaults to now)
            limit (int): Number of records per page (1-500, default 500)
            offset (int): Starting record offset (1-based, default 1)
            attributes (list): Additional attributes to include in response
            filters (dict): Filters to apply (e.g., {'osType': ['iOS', 'Android']})
            sort_by (str): Field to sort by
            order (str): Sort order 'asc' or 'desc' (default 'asc')

        Returns:
            dict: Complete response with all pages of data
        """
        # Set default time range if not provided (last 24 hours)
        if end_time is None:
            end_time = int(time.time() * 1000)
        if start_time is None:
            start_time = end_time - (24 * 60 * 60 * 1000)  # 24 hours ago

        # Check token expiration
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()

        headers = {
            'x-auth-token': self.token,
            'content-type': 'application/json'
        }

        # Build query parameters
        params = {
            'startTime': start_time,
            'endTime': end_time,
            'type': 'Wireless',  # Filter for wireless clients only
            'limit': min(limit, 500),  # API max is 500
            'offset': offset
        }

        # Add optional parameters
        if sort_by:
            params['sortBy'] = sort_by
        if order:
            params['order'] = order
        if attributes:
            for attr in attributes:
                params['attribute'] = attr

        # Add filters as query parameters
        if filters:
            for key, values in filters.items():
                if isinstance(values, list):
                    for value in values:
                        params[key] = value
                else:
                    params[key] = values

        url = f'https://{self.dnac_ip}:{self.dnac_port}/dna/data/api/v1/clients'
        all_clients = []
        total_retrieved = 0
        response = None

        try:
            while True:
                # Rate limiting: Ensure we don't exceed 50 requests per minute to avoid 429 errors
                current_time = time.time()
                
                # Reset counter every minute
                if current_time - self._rate_limit_start_time >= 60:
                    self._request_count = 0
                    self._rate_limit_start_time = current_time
                
                # If we've made 50 requests in the current minute, wait
                if self._request_count >= 50:
                    sleep_time = 60 - (current_time - self._rate_limit_start_time) + 1
                    logging.info(f'Rate limit reached (50 requests/minute). Sleeping for {sleep_time:.1f} seconds...')
                    time.sleep(sleep_time)
                    # Reset counter after waiting
                    self._request_count = 0
                    self._rate_limit_start_time = time.time()
                
                # Ensure minimum interval between requests (1.2 seconds = 50 requests/minute)
                time_since_last = current_time - self._last_request_time
                if time_since_last < 1.2:
                    sleep_time = 1.2 - time_since_last
                    logging.debug(f'Rate limiting: sleeping for {sleep_time:.2f} seconds')
                    time.sleep(sleep_time)
                
                # Update tracking variables
                self._last_request_time = time.time()
                self._request_count += 1
                
                logging.debug(f'Requesting page with offset={params["offset"]}, limit={params["limit"]} (Request #{self._request_count})')
                response = requests.get(url, headers=headers, params=params, verify=False)
                response.raise_for_status()
                
                data = response.json()
                logging.debug(f'API Response status: {response.status_code}')
                logging.debug(f'API Response: {data}')
                
                if 'response' in data and data['response']:
                    clients_page = data['response']
                    all_clients.extend(clients_page)
                    total_retrieved += len(clients_page)
                    
                    logging.info(f'Retrieved {len(clients_page)} clients, total so far: {total_retrieved}')
                    
                    # Check if we got less than requested limit (end of data)
                    if len(clients_page) < params['limit']:
                        logging.info('Retrieved all available data')
                        break
                        
                    # Update offset for next page
                    params['offset'] += params['limit']
                else:
                    logging.info('No more clients found')
                    break
                    
            # Return consolidated response
            result = {
                'response': all_clients,
                'all_clients': all_clients,
                'total_count': total_retrieved,
                'page_info': {
                    'total_pages': (total_retrieved // limit) + (1 if total_retrieved % limit > 0 else 0),
                    'records_per_page': limit,
                    'start_time': start_time,
                    'end_time': end_time
                }
            }
            
            logging.info(f'Successfully retrieved {total_retrieved} wireless clients')
            print(f"Total wireless clients retrieved: {total_retrieved}")
            print(f"Time range: {start_time} to {end_time}")
            
            return result
            
        except requests.exceptions.HTTPError as err:
            logging.error(f'HTTP Error: {err}', exc_info=True)
            if response is not None:
                try:
                    logging.error(f'Response: {response.text}')
                except:
                    logging.error('Response details unavailable')
            raise SystemExit()
        except Exception as err:
            logging.error(f'Unexpected error: {err}', exc_info=True)
            raise SystemExit()

    def get_client_enrichment_details(self, entity_value, entity_type='mac_address', 
                                      issue_category=None, persist_output=True):
        """
        Get enrichment details for a specific client using Client Enrichment Details v2 API
        Includes rate limiting to prevent 429 errors (stay under 100 API calls per minute)
        
        Args:
            entity_value (str): The MAC address or user ID of the client to query
            entity_type (str): Type of entity - 'mac_address' or 'network_user_id' (default: 'mac_address')
            issue_category (str): Optional category of issues to fetch (e.g., 'Onboarding', 'Connectivity')
            persist_output (bool): Set to True to get full enrichment details in response (default: True)
        
        Returns:
            list: Enrichment details including user details, connected devices, and issue details
        """
        if time.time() - self.token_time > 3000:
            logging.debug('token is expired.')
            self.get_token()
        
        headers = {
            'x-auth-token': self.token,
            'content-type': 'application/json',
            'entity_type': entity_type,
            'entity_value': entity_value,
            '__persistbapioutput': str(persist_output).lower()
        }
        
        # Add optional issue category header
        if issue_category:
            headers['issueCategory'] = issue_category
        
        url = f'https://{self.dnac_ip}:{self.dnac_port}/dna/intent/api/v2/client-enrichment-details'
        response = None
        
        try:
            # Rate limiting: Ensure we don't exceed 50 requests per minute to avoid 429 errors
            current_time = time.time()
            
            # Reset counter every minute
            if current_time - self._rate_limit_start_time >= 60:
                self._request_count = 0
                self._rate_limit_start_time = current_time
            
            # If we've made 50 requests in the current minute, wait
            if self._request_count >= 50:
                sleep_time = 60 - (current_time - self._rate_limit_start_time) + 1
                logging.info(f'Rate limit reached (50 requests/minute). Sleeping for {sleep_time:.1f} seconds...')
                time.sleep(sleep_time)
                # Reset counter after waiting
                self._request_count = 0
                self._rate_limit_start_time = time.time()
            
            # Ensure minimum interval between requests (1.2 seconds = 50 requests/minute)
            time_since_last = current_time - self._last_request_time
            if time_since_last < 1.2:
                sleep_time = 1.2 - time_since_last
                logging.debug(f'Rate limiting: sleeping for {sleep_time:.2f} seconds')
                time.sleep(sleep_time)
            
            # Update tracking variables
            self._last_request_time = time.time()
            self._request_count += 1
            
            logging.info(f'Getting enrichment details for {entity_type}: {entity_value} (Request #{self._request_count})')
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            
            enrichment_data = response.json()
            logging.debug(f'Enrichment response: {enrichment_data}')
            
            if enrichment_data:
                logging.info(f'Successfully retrieved enrichment details for {entity_value}')
                return enrichment_data
            else:
                logging.warning(f'No enrichment data found for {entity_value}')
                return []
                
        except requests.exceptions.HTTPError as err:
            logging.error(f'HTTP Error getting enrichment details: {err}', exc_info=True)
            if response is not None:
                try:
                    logging.error(f'Response: {response.text}')
                except:
                    logging.error('Response details unavailable')
            return []
        except Exception as err:
            logging.error(f'Unexpected error getting enrichment details: {err}', exc_info=True)
            return []
