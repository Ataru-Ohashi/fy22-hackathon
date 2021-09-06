import base64
import json
import logging
import os
import re
import sys
from time import sleep
import traceback

from flask import Flask, request
import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning

__updated__ = "2021-08-27"

with open("dictionary.json", "r", encoding="utf-8_sig") as f:
    json_dict = json.load(f)
app = Flask(__name__)
driver = None
umbrella_driver = None
amp4e_driver = None


#===============================================================================
# load_json_file
#===============================================================================
def load_json_file(file_path):
    """
    Load the JSON file.
    If there is no file, an empty dict is returned.

    Parameters
    ----------
    file_path : str
        JSON file path

    Returns
    -------
    _ : dict
        parameter map

    Raises
    ------
    """
    if not os.path.isfile(file_path):
        logger = logging.getLogger(__name__)
        logger.warning(f"File not found: {file_path}")
        return {}

    with open(file_path, "r") as f:
        return json.load(f)


#===============================================================================
# base64_encode
#===============================================================================
def base64_encode(inputStr):
    """
    Encode strings in Base64.
    Internally, it is encoded by converting it to a byte sequence once, and then decoded into str.

    Parameters
    ----------
    inputStr : str
        String to be encoded

    Returns
    -------
    _ : str
        encoded string

    Raises
    ------
    """
    return base64.b64encode(inputStr.encode()).decode()


#===============================================================================
# CiscoAPIDriver
#===============================================================================
class CiscoAPIDriver:
    """
    Super class for each API driver
    """

    #===========================================================================
    # __init__
    #===========================================================================
    def __init__(self, verify=True, logger=None):
        self.verify = verify
        self.logger = logger or logging.getLogger(__name__)
        return

    #===========================================================================
    # _send_http_request
    #===========================================================================
    def _send_http_request(self, api, header=None, payload=None, return_all=False):
        """
        A common process for sending HTTP requests and receiving HTTP responses.
        Check the return code, and the data will be checked by the caller.

        Parameters
        ----------
        api : tuple
            Tuple of HTTP requests and destination URLs to use

        header : dict, default None
            Request header

        payload : dict, default None
            Query data to be attached to the request
            Connect to the URL for GET, or embed it in the Body for POST

        return_all : bool, default False
            Set to True if the entire response data is to be returned.
            By default, it is converted to dictionary format and returned.

        Returns
        -------
        ret : dict or Response or None
            Return response data as a whole or in a converted format
            None if the request fails.

        Raises
        ------
        """
        self.logger.debug("{} START".format(sys._getframe().f_code.co_name))
        ret = None
        try_limit = 3  # three attempts for now.
        retry_interval = 5
        for _ in range(1, try_limit, 1):
            try:
                self.logger.debug("Request URL: [{}] {}".format(api[0], api[1]))

                # Send request
                if api[0] == "GET":
                    res = requests.get(api[1], headers=header, params=payload, verify=self.verify)
                elif api[0] == "POST":
                    res = requests.post(api[1], headers=header, data=json.dumps(payload), verify=self.verify)

                # Send exception when return code is not 200 units.
                res.raise_for_status()

                status_code = res.status_code
                self.logger.debug(f"Return Code: {status_code}")
                ret = res if return_all else res.json()
                break

            # Re-run for connection error
            except (requests.exceptions.ProxyError, requests.exceptions.ConnectionError) as e:
                self.logger.exception(f"HTTP connection error: {e}")
                sleep(retry_interval)

            # Exceptions other than the above are abnormal termination.
            except Exception as e:
                self.logger.exception(f"Unexpected error: {e}")
                if res is not None:
                    self.logger.error(f"Return data: {res.text}")
                break

        self.logger.debug("{} END".format(sys._getframe().f_code.co_name))
        return ret

#------------------------------------------------------------------------------ CiscoAPIDriver end


#===============================================================================
# DNACDriver
#===============================================================================
class DNACDriver(CiscoAPIDriver):

    #===========================================================================
    # __init__
    #===========================================================================
    def __init__(self, verify=True, logger=None):
        super().__init__(verify=verify, logger=logger)
        config = load_json_file("config.json")
        self.hostname = config["hostname"]
        self.username = config["username"]
        self.password = config["password"]
        self.zip_pass = config["zip_pass"]
        self.api_key = base64_encode(f"{self.username}:{self.password}")
        api = config["api"]["authenticationAPI"]
        self.authentication_api = (api[0], self.__create_url(api[1]))
        api = config["api"]["getDeviceList"]
        self.get_device_list_api = (api[0], self.__create_url(api[1]))
        api = config["api"]["exportDeviceConfigurations"]
        self.export_device_config_api = (api[0], self.__create_url(api[1]))
        api = config["api"]["getTaskById"]
        self.get_task_by_id_api = (api[0], self.__create_url(api[1]))
        api = config["api"]["downloadAFileByFileId"]
        self.download_a_file_by_file_id_api = (api[0], self.__create_url(api[1]))
        api = config["api"]["getClientDetail"]
        self.get_client_detail_api = (api[0], self.__create_url(api[1]))
        api = config["api"]["getClientEnrichmentDetails"]
        self.get_client_enrichment_details_api = (api[0], self.__create_url(api[1]))

        self.token = None
        return

    #===========================================================================
    # __create_url
    #===========================================================================
    def __create_url(self, api_path):
        """
        Connect the protocol and FQDN to the path, and generate a URL for HTTP request.

        Parameters
        ----------
        api_path : str
            API path
            Must be preceded by a slash "/".

        Returns
        -------
        _ : str
            HTTP request URL
            If the path is None (no setting), return None.

        Raises
        ------
        """
        if api_path is None: return None
        return f"https://{self.hostname}:443{api_path}"

    #===========================================================================
    # __create_header
    #===========================================================================
    def __create_header(self, append=None, token=None):
        """
        Generate HTTP request headers.
        Set the following header information in common.
            - Content-Type
            - Accept
            - x-auth-token

        Parameters
        ----------
        append : dict, default None
            Map of header information to be set additionally

        token : str, default None
            Set to specify the token required for the request from outside.
            If not set, use the token held in the instance

        Returns
        -------
        ret : dict
            HTTP request header

        Raises
        ------
        """
        ret = {"Content-Type":"application/json",
               "Accept": "application/json",
               "x-auth-token": token or self.token}
        if append is not None: ret.update(append)
        return ret

    #===========================================================================
    # get_token
    #===========================================================================
    def get_token(self):
        """
        Obtain the token required when making a request to the API.
        If you do not run this method first, you will not get the tokens needed for subsequent requests.
        Since the token is also recorded inside the instance, it is not necessary to specify the token if the instance is to be retained.

        Parameters
        ----------

        Returns
        -------
        _ : str or None
            Return the token
            None if the request fails.

        Raises
        ------
        """
        header = self.__create_header(append={"Authorization": f"Basic {self.api_key}"})
        data = self._send_http_request(self.authentication_api, header=header)
        if data is None: return None

        self.token = data["Token"]
        return self.token

    #===========================================================================
    # get_devices
    #===========================================================================
    def get_devices(self, hostname=None, token=None):
        """
        Get a list of the specified devices.
        If no condition is specified, all devices registered in DNAC are acquired.

        Parameters
        ----------
        hostname : str, default None
            Set to specify the host name of the device.
            Wildcards can be used.

        token : str, default None
            Set to specify the token required for the request from outside.
            If not set, use the token held in the instance

        Returns
        -------
        _ : list or None
            Return the list of devices
            None if the request fails.

        Raises
        ------
        """
        header = self.__create_header(token=token)
        payload = {}
        if hostname is not None:
            payload["hostname"] = hostname
        data = self._send_http_request(self.get_device_list_api,
                                       header=header,
                                       payload=payload if len(payload) else None)
        if data is None: return None

        return data["response"]

    #===========================================================================
    # kick_export_configs
    #===========================================================================
    def kick_export_configs(self, ids, token=None):
        """
        Exports the Config of the specified device in encrypted Zip format.
        Config is output in clear text format, and passwords and other character strings are not masked.
        The password for the encrypted Zip is "[username]:[password]".
        This only kicks off the export process, not the download.

        Parameters
        ----------
        ids : list
            ID list of devices to be Config output

        token : str, default None
            Set to specify the token required for the request from outside.
            If not set, use the token held in the instance.

        Returns
        -------
        _ : list or None
            Return the task ID of the export process.
            None if the request fails.

        Raises
        ------
        """
        header = self.__create_header(token=token)
        payload = {"deviceId": ids,
                   "password": self.zip_pass}
        data = self._send_http_request(self.export_device_config_api, header=header, payload=payload)
        if data is None: return None

        return data["response"]["taskId"]

    #===========================================================================
    # get_task_status
    #===========================================================================
    def get_task_status(self, task_id, token=None):
        """
        Get the status of the specified task.

        Parameters
        ----------
        task_id : str
            ID of the target task

        token : str, default None
            Set to specify the token required for the request from outside.
            If not set, use the token held in the instance.

        Returns
        -------
        _ : list or None
            Response data
            None if the request fails.

        Raises
        ------
        """
        header = self.__create_header(token=token)
        api = (self.get_task_by_id_api[0],
               self.get_task_by_id_api[1].format(taskId=task_id))
        data = self._send_http_request(api, header=header)
        if data is None: return None

        return data["response"]

    #===========================================================================
    # download_file
    #===========================================================================
    def download_file(self, file_id=None, additional_status_url=None, token=None):
        """
        Download the specified file.
        Either a file ID or an additional URL should be specified.
        If both are specified, the file ID has priority.
        If both are not specified, false is returned.

        Parameters
        ----------
        file_id : str, default None
            ID of the target file

        additional_status_url : str, default None
            Download URL obtained from the file generation task

        token : str, default None
            Set to specify the token required for the request from outside.
            If not set, use the token held in the instance.

        Returns
        -------
        _ : bool
            True if the download was successful.
            Otherwise, False.

        Raises
        ------
        """
        header = self.__create_header(token=token)
        if file_id is not None:
            api = (self.download_a_file_by_file_id_api[0],
                   self.download_a_file_by_file_id_api[1].format(fileId=file_id))
        elif additional_status_url is not None:
            api = (self.download_a_file_by_file_id_api[0],
                   self.__create_url(additional_status_url))
        else:
            self.logger.warning("It is mandatory to set either 'file_id' or 'additional_status_url'")
            return False

        res = self._send_http_request(api, header=header, return_all=True)
        if res is None: return False

        # Get the file name from the response header
        content_disposition = res.headers["Content-Disposition"]
        filename_attribute = "filename="
        filename = content_disposition[content_disposition.find(filename_attribute) + len(filename_attribute):]
        filename = filename.replace("\"", "")

        # File output as binary data
        with open(filename, "wb") as f:
            f.write(res.content)

        return True

    #===========================================================================
    # get_client
    #===========================================================================
    def get_client(self, mac, timestamp=None, token=None):
        """
        Get detailed information about the specified client.

        Parameters
        ----------
        mac : str
            MAC address of the target client

        timestamp : int or None, default blank
            Set when you want to get information for a specific time.
            The set value is the epoch time (in milliseconds).
            If not set, get the latest information

        token : str, default None
            Set to specify the token required for the request from outside.
            If not set, use the token held in the instance.

        Returns
        -------
        _ : dict or None
            Response data
            None if the request fails.

        Raises
        ------
        """
        header = self.__create_header(token=token)
        payload = {"timestamp": "" if timestamp is None else str(timestamp),
                   "macAddress": mac}
        data = self._send_http_request(self.get_client_detail_api, header=header, payload=payload)
        if data is None: return None

        return data

    #===========================================================================
    # get_client_enrichment
    #===========================================================================
    def get_client_enrichment(self, entity_type, entity_value, issue_category=None, token=None):
        """
        Get the anomalies and remedies occurring in the specified client.

        Parameters
        ----------
        entity_type : str
            Key to identify the target client.
            "network_user_id" or "mac_address"

        entity_value : str
            Parameters for the key
            User ID or MAC address

        issue_category : str, default None
            Set to refine the category of the event.

        token : str, default None
            Set to specify the token required for the request from outside.
            If not set, use the token held in the instance.

        Returns
        -------
        _ : dict or None
            Response data
            None if the request fails.

        Raises
        ------
        """
        header = self.__create_header(append={"entity_type": entity_type,
                                              "entity_value": entity_value,
                                              "issueCategory": "" if issue_category is None else issue_category},
                                      token=token)
        data = self._send_http_request(self.get_client_enrichment_details_api, header=header)
        if data is None: return None

        # HTTP response is 200, but there is a pattern of errors in the data.
        if "errorCode" in data:
            self.logger.error("Return error : [{}] {}".format(data["errorCode"], data["errorDescription"]))
            return None

        return data

    #===========================================================================
    # get_client_enrichment_by_mac
    #===========================================================================
    def get_client_enrichment_by_mac(self, mac, issue_category=None, token=None):
        """
        get_client_enrichment() wrapper function.
        """
        return self.get_client_enrichment("mac_address", mac, issue_category, token)

    #===========================================================================
    # get_client_enrichment_by_uid
    #===========================================================================
    def get_client_enrichment_by_uid(self, uid, issue_category=None, token=None):
        """
        get_client_enrichment() wrapper function.
        """
        return self.get_client_enrichment("network_user_id", uid, issue_category, token)

#------------------------------------------------------------------------------ DNACDriver end


#===============================================================================
# UmbrellaDriver
#===============================================================================
class UmbrellaDriver(CiscoAPIDriver):

    #===========================================================================
    # __init__
    #===========================================================================
    def __init__(self, verify=True, logger=None):
        super().__init__(verify=verify, logger=logger)
        config = load_json_file("config.json")
        self.api_key = config["umbrella_api_key"]
        self.authentication_api = config["umbrella_api"]["authentication"]
        self.reporting_activity_api = config["umbrella_api"]["reportingActivity"]

        self.token = None
        return

    #===========================================================================
    # __create_header
    #===========================================================================
    def __create_header(self, append=None, token=None):
        """
        Generate HTTP request headers.
        Set the following header information in common.
            - Content-Type
            - Authorization

        Parameters
        ----------
        append : dict, default None
            Map of header information to be set additionally

        token : str, default None
            Set to specify the token required for the request from outside.
            If not set, use the token held in the instance.

        Returns
        -------
        ret : dict
            HTTP request header

        Raises
        ------
        """
        ret = {"Content-Type":"application/json",
               "Authorization": "Bearer {}".format(token or self.token)}
        if append is not None: ret.update(append)
        return ret

    #===========================================================================
    # get_token
    #===========================================================================
    def get_token(self):
        """
        Obtain the token required when making a request to the API.
        If you do not run this method first, you will not get the tokens needed for subsequent requests.
        Since the token is also recorded inside the instance, it is not necessary to specify the token if the instance is to be retained.

        Parameters
        ----------

        Returns
        -------
        _ : dict or None
            Response data
            None if the request fails.

        Raises
        ------
        """
        header = self.__create_header(append={"Authorization": f"Basic {self.api_key}"})
        data = self._send_http_request(self.authentication_api, header=header)
        if data is None: return None

        self.token = data["access_token"]
        return data

    #===========================================================================
    # get_activity
    #===========================================================================
    def get_activity(self, org_id, term_from, term_to, list_limit, act_type="all", act_category=None, ip=None, token=None):
        """
        Get a list of Umbrella's activities within the specified period.

        Parameters
        ----------
        org_id : str
            ID of the target organization

        term_from : str or int
            Start time of the period
            Serial value of timestamp (e.g. 14205322422) or string of relative time (e.g. -1days)

        term_to : str or int
            End time of the period
            Serial value of timestamp (e.g. 14205322422) or string of relative time (e.g. -1days)

        list_limit : int
            Maximum number of activities to retrieve

        act_type : str, default "all"
            Set if you want to filter by activity type.
            Valid values are dns/proxy/firewall/ip
            If omitted or an invalid value is specified, do not filter.

        act_category : str, default None
            Set if you want to filter by activity category.
            Specify the category ID as a comma-separated list

        ip : str, default None
            Set if you want to filter by client IP address.

        token : str, default None
            Set to specify the token required for the request from outside.
            If not set, use the token held in the instance.

        Returns
        -------
        _ : list or None
            Response data
            None if the request fails.

        Raises
        ------
        """
        header = self.__create_header(token=token)
        protocol = self.reporting_activity_api[0]
        url = self.reporting_activity_api[1].format(organizationid=org_id)
        if act_type in ["dns", "proxy", "firewall", "ip"]:
            url += "/" + act_type
        payload = {"from": term_from,
                   "to": term_to,
                   "limit": list_limit,
                   "categories": "" if act_category is None else act_category,
                   "ip": "" if ip is None else ip}

        # In requests.get(), comma is converted to "%2C" when generating query string, so URL with query must be generated and passed.
        # https://stackoverflow.com/questions/56734910/python-converting-in-requests-get-parameters-to-2c-and-to-7c
        url += "?" + "&".join([f"{k}={v}" for k, v in payload.items()])

        data = self._send_http_request((protocol, url), header=header)
        if data is None: return None

        return data

#------------------------------------------------------------------------------ UmbrellaDriver end


#===============================================================================
# AMP4EDriver
#===============================================================================
class AMP4EDriver(CiscoAPIDriver):

    #===========================================================================
    # __init__
    #===========================================================================
    def __init__(self, verify=True, logger=None):
        super().__init__(verify=verify, logger=logger)
        config = load_json_file("config.json")
        url = "https://{}".format(config["amp4e_hostname"])
        self.uid = config["amp4e_id"]
        self.password = config["amp4e_key"]
        self.api_key = base64_encode(f"{self.uid}:{self.password}")
        api = config["amp4e_api"]["computers"]
        self.computers_api = (api[0], url + api[1])
        api = config["amp4e_api"]["events"]
        self.events_api = (api[0], url + api[1])
        return

    #===========================================================================
    # __create_header
    #===========================================================================
    def __create_header(self, append=None):
        """
        Generate HTTP request headers.
        Set the following header information in common.
            - Accept
            - Content-Type
            - Accept-Encoding
            - Authorization

        Parameters
        ----------
        append : dict, default None
            Map of header information to be set additionally

        Returns
        -------
        ret : dict
            HTTP request header

        Raises
        ------
        """
        ret = {"Accept": "application/json",
               "Content-Type":"application/json",
               "Accept-Encoding": "identity, gzip, deflate",
               "Authorization": f"Basic {self.api_key}"}
        if append is not None: ret.update(append)
        return ret

    #===========================================================================
    # get_computers
    #===========================================================================
    def get_computers(self, list_limit, list_offset=0, ip=None):
        """
        Get the list of specified host computers.

        Parameters
        ----------
        list_limit : int
            Maximum number of lists

        list_offset : int, default 0
            Start position for getting the list

        ip : str, default None
            Set to filter by IP address of the host computer.
            The address band can be specified by omitting the end (wildcards are not required)

        Returns
        -------
        _ : list or None
            Response data
            None if the request fails.

        Raises
        ------
        """
        payload = {"limit": list_limit,
                   "offset": list_offset,
                   "internal_ip": "" if ip is None else ip}
        data = self._send_http_request(self.computers_api,
                                       header=self.__create_header(),
                                       payload=payload)
        if data is None: return None

        return data

    #===========================================================================
    # get_events
    #===========================================================================
    def get_events(self, list_limit, list_offset=0, connector_guid=None):
        """
        Get a list of the specified events.

        Parameters
        ----------
        list_limit : int
            Maximum number of lists

        list_offset : int, default 0
            Start position for getting the list

        connector_guid : str, default None
            Set to filter by Connector GUID

        Returns
        -------
        _ : list or None
            Response data
            None if the request fails.

        Raises
        ------
        """
        payload = {"limit": list_limit,
                   "offset": list_offset,
                   "connector_guid[]": "" if connector_guid is None else connector_guid}
        data = self._send_http_request(self.events_api,
                                       header=self.__create_header(),
                                       payload=payload)
        if data is None: return None

        return data

#------------------------------------------------------------------------------ AMP4EDriver end


#===============================================================================
# get_request
#===============================================================================
@app.route("/")
def get_request():
    value = request.args.get("text", "")
    callback = request.args.get("callback", "")

    if re.compile(r"([a-fA-F0-9]{2}\:){5}[a-fA-F0-9]{2}").search(value):
        resp = dnac_client_enrich(mac=value)
    elif re.compile(r"uid-").search(value):
        resp = dnac_client_enrich(uid=value[4:])
    elif re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").search(value):
        resp = umbrella_report(value)
        resp2 = amp4e_event(value)
        resp.extend(resp2)
    else:
        # Display a default message when an unexpected request comes in.
        if value not in json_dict: value = "bad condition"
        resp = [{"type": "text",
                 "value": json_dict[value]}]

    contents = callback + "(" + json.dumps({"output": resp}) + ")"
    return contents


#===============================================================================
# dnac_client_enrich
#===============================================================================
def dnac_client_enrich(mac=None, uid=None):
    resp = []
    try:
        token = driver.get_token()
        if token is None:
            return [{"type": "text",
                     "value": "failed to query DNAC.<br>please wait for a while and try again."}]

        if uid is None:
            enrichs = driver.get_client_enrichment_by_mac(mac)
            if enrichs is None:
                return [{"type": "text",
                         "value": "<br>".join([f"can not find client having MAC '{mac}'.",
                                               "please confirm and input MAC (format: 'XX:XX:XX:XX:XX:XX') again."])}]
            # Get only the first one.
            enrich = enrichs[0]
            if not (len(enrich["userDetails"]) and len(enrich["connectedDevice"])):
                return [{"type": "text",
                         "value": "<br>".join(["can not get client information normally.",
                                               "please wait a sec and retry."])}]
            # issue_count = enrich["userDetails"]["issueCount"]
            issue_details = enrich["issueDetails"]

        else:
            enrichs = driver.get_client_enrichment_by_uid(uid)
            if enrichs is None:
                return [{"type": "text",
                         "value": "<br>".join([f"can not find client logging in user '{uid}'.",
                                               "please confirm and input UserID (format: uid-&lt;userid&gt; / e.g. uid-taro) again."])}]
            # Get only the first one.
            enrich = enrichs[0]
            if not (len(enrich["userDetails"]) and len(enrich["connectedDevice"])):
                return [{"type": "text",
                         "value": "<br>".join(["can not get client information normally.",
                                               "please wait a sec and retry."])}]
            mac = enrich["userDetails"]["hostMac"]
            # issue_count = enrich["userDetails"]["issueCount"]
            issue_details = enrich["issueDetails"]

        client = driver.get_client(mac)
        if client is None:
            return [{"type": "text",
                     "value": f"can not find client having MAC '{mac}'.<br>please contact IT department."}]
        elif not (len(client["connectionInfo"]) and len(client["detail"]) and len(client["topology"])):
            return [{"type": "text",
                     "value": "<br>".join(["can not get client information normally.",
                                           "please wait a sec and retry."])}]
        conn_status = client["detail"]["connectionStatus"]
        host_ip = client["detail"]["hostIpV4"]
        host_name = client["detail"]["hostName"]
        host_type = client["detail"]["hostType"]
        ssid = client["detail"]["ssid"]
        host_location = client["detail"]["location"]
        port = client["detail"]["port"]
        link_speed = client["detail"]["linkSpeed"]
        host_score = client["detail"]["healthScore"][0]["score"]
        # If the connection is broken and only the client data is left, the connectionInfo will contain error information.
        band = client["connectionInfo"].get("band", "----")
        channel_width = client["connectionInfo"].get("channelWidth", "----")
        device_name = client["connectionInfo"].get("nwDeviceName", "----")

        resp.append({"type": "text",
                     "value": "querying DNAC is successful.<br>please confirm here.",
                     "delayMs": 500})

        if host_type == "WIRED":
            resp.append({"type": "text",
                         "value": "<br>".join([f"Hostname: {host_name}",
                                               f"IP: {host_ip}",
                                               f"Location: {host_location}",
                                               f"Health Score: {host_score}",
                                               f"Connection Type: {host_type}",
                                               f"Connection Status: {conn_status}",
                                               f"Connected Device: {device_name}",
                                               f"Interface: {port}",
                                               f"Link Speed: {link_speed} bps"]),
                         "delayMs": 2000})
        else:
            resp.append({"type": "text",
                         "value": "<br>".join([f"Hostname: {host_name}",
                                               f"IP: {host_ip}",
                                               f"Location: {host_location}",
                                               f"Health Score: {host_score}",
                                               f"Connection Type: {host_type}",
                                               f"Connection Status: {conn_status}",
                                               f"Connected AP: {device_name}",
                                               f"Connected SSID: {ssid}",
                                               f"Bandwidth: {band} GHz",
                                               f"Channel Width: {channel_width} MHz"]),
                         "delayMs": 2000})

        if len(issue_details) == 0:
            resp.append({"type": "text",
                         "value": "your device has no issue.<br>but if health score is low, please contact IT department.",
                         "delayMs": 2000})
        else:
            resp.append({"type": "text",
                         "value": "your device has some issues.",
                         "delayMs": 2000})

            for i, issue in enumerate(issue_details["issue"]):
                resp.append({"type": "text",
                             "value": "issue {} : {}".format(i + 1, issue["issueSummary"]),
                             "delayMs": 2000})

                for j, action in enumerate(issue["suggestedActions"]):
                    resp.append({"type": "text",
                                 "value": "suggested action {}-{} : {}".format(i + 1, j + 1, action["message"]),
                                 "delayMs": 2000})

            resp.append({"type": "text",
                         "value": "<br>".join(["if you do above suggested actions, issues may be resolved.",
                                               "if issues are not resolved, please contact IT department."]),
                         "delayMs": 2000})

        # We'll also get information about Umbrella and AMP4E.
        resp.append({"type": "text",
                     "value": "moving on to the security check...",
                     "delayMs": 2000})

        umbrella_resp = umbrella_report(host_ip)
        resp.extend(umbrella_resp)

        amp4e_resp = amp4e_event(host_ip)
        resp.extend(amp4e_resp)

    except KeyError:
        traceback.print_exc()
        return [{"type": "text",
                 "value": "unexpected error has occured.<br>please contact IT department."}]

    return resp


#===============================================================================
# umbrella_report
#===============================================================================
def umbrella_report(ip):
    resp = []

    umbrella_driver.get_token()

    # TODO: For demonstration purposes, some filtering conditions are fixed.
    org_id = "2067079"
    term_from = "-1days"
    term_to = "now"
    list_limit = 5
    act_category = "68,66,64"  # Filtering by Malware, Phishing, and C&C categories
    response_report = umbrella_driver.get_activity(org_id,
                                                   term_from,
                                                   term_to,
                                                   list_limit,
                                                   act_category=act_category,
                                                   ip=ip)

    resp.append({"type": "text",
                 "value": "querying Umbrella is successful.<br>please confirm here.",
                 "delayMs": 500 })

    activities = response_report["data"]
    if len(activities) == 0:
        resp.append({"type": "text",
                     "value": "lucky day! there is no malicious domain you queried recently.",
                     "delayMs": 2000 })
    else:
        resp.append({"type": "text",
                     "value": "the following domains you have recently accessed are likely to be <font color=\"#ff0000\"><b>malicious</b></font> domains.",
                     "delayMs": 2000 })

        domains = []
        for i, activity in enumerate(activities):
            domains.append("{}. {}".format((i + 1), activity["domain"]))

        resp.append({"type": "text",
                     "value": "<br>".join(domains),
                     "delayMs": 2000})

    return resp


#===============================================================================
# amp4e_event
#===============================================================================
def amp4e_event(ip):
    resp = []

    # TODO: For demonstration purposes, some filtering conditions are fixed.
    list_limit = 5
    data = amp4e_driver.get_computers(list_limit, ip=ip)
    computers = data["data"]
    if len(computers) == 0:
        return [{"type": "text",
                 "value": "you do not have the AMP4E agent installed on your device. please contact IT department to install the agent."}]

    # If AMP4E is already installed on the device, get event information
    data = amp4e_driver.get_events(list_limit, connector_guid=computers[0]["connector_guid"])

    resp.append({"type": "text",
                 "value": "querying AMP4E is successful.<br>please confirm here.",
                 "delayMs": 500 })

    events = data["data"]
    if len(events) == 0:
        resp.append({"type": "text",
                     "value": "lucky day! there is no malicious event you queried recently.",
                     "delayMs": 2000 })
    else:
        resp.append({"type": "text",
                     "value": "the following events are likely to be <font color=\"#ff0000\"><b>malicious</b></font> events.",
                     "delayMs": 2000 })

        detections = []
        for i, event in enumerate(events):
            detections.append("{}. {}".format((i + 1), event["event_type"]))
            detections.append("-- Name: {}".format(event["detection"]))
            detections.append("-- Time: {}".format(event["date"]))
            if "file_name" in event["file"]:
                detections.append("-- File: {}".format(event["file"]["file_name"]))

        resp.append({"type": "text",
                     "value": "<br>".join(detections),
                     "delayMs": 2000})

    return resp


if __name__ == "__main__":
    # If DNAC uses a self-certificate, an error will occur when verifying the SSL certificate, so turn off verification.
    # If you turn off verification, you will get an InsecureRequestWarning, ignore that too.
    urllib3.disable_warnings(InsecureRequestWarning)
    driver = DNACDriver(verify=False)
    umbrella_driver = UmbrellaDriver()
    amp4e_driver = AMP4EDriver()

    app.run(debug=True)

