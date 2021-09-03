# -*- coding: Shift-JIS -*-
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
    JSON�t�@�C�������[�h����B
    �t�@�C���������ꍇ�͋��dict��ԋp����B

    Parameters
    ----------
    file_path : str
        JSON�t�@�C���p�X

    Returns
    -------
    _ : dict
        �p�����[�^�}�b�v

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
    �������Base64�ŃG���R�[�h����B
    �����I�ɂ́A��Ubyte��ɕϊ����ăG���R�[�h���Ă���str�Ƀf�R�[�h���Ă���B

    Parameters
    ----------
    inputStr : str
        �G���R�[�h�Ώە�����

    Returns
    -------
    _ : str
        �G���R�[�h�ςݕ�����

    Raises
    ------
    """
    return base64.b64encode(inputStr.encode()).decode()


#===============================================================================
# CiscoAPIDriver
#===============================================================================
class CiscoAPIDriver:
    """
    �eAPI�h���C�o�[�̃X�[�p�[�N���X
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
        HTTP���N�G�X�g�̑��M�ƁAHTTP���X�|���X�̎�M���s�����ʏ����B
        ���^�[���R�[�h�̊m�F�܂ōs���A�f�[�^�̊m�F�͌Ăь��ōs���B

        Parameters
        ----------
        api : tuple
            �g�p����HTTP���N�G�X�g�ƃ��N�G�X�g��URL�̃^�v��

        header : dict, default None
            ���N�G�X�g�w�b�_�[

        payload : dict, default None
            ���N�G�X�g�ɓY�t����N�G���f�[�^
            GET�Ȃ�URL�ɐڑ����APOST�Ȃ�Body�ɑg�ݍ���

        return_all : bool, default False
            ���X�|���X�f�[�^�S�̂�ԋp����ꍇ�� True ��ݒ�
            �f�t�H���g�ł̓f�B�N�V���i���`���ɕϊ����ĕԋp����

        Returns
        -------
        ret : dict or Response or None
            ���X�|���X�f�[�^��S�̂܂��͕ϊ���̌`���ŕԋp
            ���N�G�X�g�Ɏ��s�����ꍇ��None

        Raises
        ------
        """
        self.logger.debug("{} START".format(sys._getframe().f_code.co_name))
        ret = None
        try_limit = 3  # �Ƃ肠����3�񎎍s�ł���悤�ɂ��Ă���
        retry_interval = 5
        for _ in range(1, try_limit, 1):
            try:
                self.logger.debug("Request URL: [{}] {}".format(api[0], api[1]))

                # ���N�G�X�g���M
                if api[0] == "GET":
                    res = requests.get(api[1], headers=header, params=payload, verify=self.verify)
                elif api[0] == "POST":
                    res = requests.post(api[1], headers=header, data=json.dumps(payload), verify=self.verify)

                # ���^�[���R�[�h�� 200 ��łȂ��ꍇ�ɗ�O�𑗏o
                res.raise_for_status()

                status_code = res.status_code
                self.logger.debug(f"Return Code: {status_code}")
                ret = res if return_all else res.json()
                break

            # �ڑ��G���[�n�͍Ď��s
            except (requests.exceptions.ProxyError, requests.exceptions.ConnectionError) as e:
                self.logger.exception(f"HTTP connection error: {e}")
                sleep(retry_interval)

            # ��L�ȊO�̗�O�ُ͈�I��
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
        �p�X�Ƀv���g�R����FQDN��ڑ����AHTTP���N�G�X�g�pURL�𐶐�����B

        Parameters
        ----------
        api_path : str
            API�p�X
            �擪�̓X���b�V�� "/" �ł��邱��

        Returns
        -------
        _ : str
            HTTP���N�G�X�gURL
            �p�X��None�i�ݒ肪�����j�̏ꍇ��None��ԋp����

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
        HTTP���N�G�X�g�w�b�_�𐶐�����B
        ���ʂňȉ��̃w�b�_����ݒ肷��B
            - Content-Type
            - Accept
            - x-auth-token

        Parameters
        ----------
        append : dict, default None
            �ǉ��Őݒ肷��w�b�_���̃}�b�v

        token : str, default None
            ���N�G�X�g�ɕK�v�ȃg�[�N�����O������w�肷��ꍇ�ɐݒ�
            �ݒ肵�Ȃ��ꍇ�A�C���X�^���X���ɕێ����Ă���g�[�N�����g�p����

        Returns
        -------
        ret : dict
            HTTP���N�G�X�g�w�b�_

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
        API�ւ̃��N�G�X�g���ɕK�v�ȃg�[�N�����擾����B
        �ŏ��ɂ��̃��\�b�h�����s���Ȃ��ƁA�ȍ~�̃��N�G�X�g�ɕK�v�ȃg�[�N���������Ȃ��B
        �g�[�N���̓C���X�^���X�����ɂ��L�^���邽�߁A�C���X�^���X��ێ�����ꍇ�̓g�[�N�����w�肷��K�v�͖����B

        Parameters
        ----------

        Returns
        -------
        _ : str or None
            �g�[�N����ԋp
            ���N�G�X�g�Ɏ��s�����ꍇ��None

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
        �w�肵���f�o�C�X�̃��X�g���擾����B
        �������w�肵�Ȃ��ꍇ�ADNAC�ɓo�^����Ă���S�Ẵf�o�C�X���擾����B

        Parameters
        ----------
        hostname : str, default None
            �f�o�C�X�̃z�X�g�����w�肷��ꍇ�ɐݒ�
            ���C���h�J�[�h�g�p��

        token : str, default None
            ���N�G�X�g�ɕK�v�ȃg�[�N�����O������w�肷��ꍇ�ɐݒ�
            �ݒ肵�Ȃ��ꍇ�A�C���X�^���X���ɕێ����Ă���g�[�N�����g�p����

        Returns
        -------
        _ : list or None
            �f�o�C�X�̃��X�g��ԋp
            ���N�G�X�g�Ɏ��s�����ꍇ��None

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
        �w�肵���f�o�C�X��Config���Í���Zip�`���ŃG�N�X�|�[�g����B
        Config�̓N���A�e�L�X�g�`���ŏo�͂���A�p�X���[�h���̕�����̓}�X�N����Ȃ��B
        �Í���Zip�̃p�X���[�h�́u[���[�U��]�F[�p�X���[�h]�v�ƂȂ�B
        �������ł̓G�N�X�|�[�g�������L�b�N���邾���ŁA�_�E�����[�h�͂ł��Ȃ��B

        Parameters
        ----------
        ids : list
            Config�o�͑ΏۂƂȂ�f�o�C�X��ID���X�g

        token : str, default None
            ���N�G�X�g�ɕK�v�ȃg�[�N�����O������w�肷��ꍇ�ɐݒ�
            �ݒ肵�Ȃ��ꍇ�A�C���X�^���X���ɕێ����Ă���g�[�N�����g�p����

        Returns
        -------
        _ : list or None
            �G�N�X�|�[�g�v���Z�X�̃^�X�NID��ԋp
            ���N�G�X�g�Ɏ��s�����ꍇ��None

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
        �w�肵���^�X�N�̏�Ԃ��擾����B

        Parameters
        ----------
        task_id : str
            �Ώۃ^�X�N��ID

        token : str, default None
            ���N�G�X�g�ɕK�v�ȃg�[�N�����O������w�肷��ꍇ�ɐݒ�
            �ݒ肵�Ȃ��ꍇ�A�C���X�^���X���ɕێ����Ă���g�[�N�����g�p����

        Returns
        -------
        _ : list or None
            ���X�|���X�f�[�^
            ���N�G�X�g�Ɏ��s�����ꍇ��None

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
        �w�肵���t�@�C�����_�E�����[�h����B
        �t�@�C��ID�܂��͒ǉ�URL�̂����ꂩ���w�肷�邱�ƁB
        �������w�肵���ꍇ�̓t�@�C��ID��D�悷��B
        �������w�肵�Ȃ��ꍇ��False��ԋp����B

        Parameters
        ----------
        file_id : str, default None
            �Ώۃt�@�C����ID

        additional_status_url : str, default None
            �t�@�C�������^�X�N������肵���_�E�����[�hURL

        token : str, default None
            ���N�G�X�g�ɕK�v�ȃg�[�N�����O������w�肷��ꍇ�ɐݒ�
            �ݒ肵�Ȃ��ꍇ�A�C���X�^���X���ɕێ����Ă���g�[�N�����g�p����

        Returns
        -------
        _ : bool
            �_�E�����[�h�ɐ��������ꍇ��True
            ����ȊO�̏ꍇ��False

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

        # ���X�|���X�w�b�_����t�@�C�������擾
        content_disposition = res.headers["Content-Disposition"]
        filename_attribute = "filename="
        filename = content_disposition[content_disposition.find(filename_attribute) + len(filename_attribute):]
        filename = filename.replace("\"", "")

        # �o�C�i���f�[�^�Ƃ��ăt�@�C���o��
        with open(filename, "wb") as f:
            f.write(res.content)

        return True

    #===========================================================================
    # get_client
    #===========================================================================
    def get_client(self, mac, timestamp=None, token=None):
        """
        �w�肵���N���C�A���g�̏ڍ׏����擾����B

        Parameters
        ----------
        mac : str
            �ΏۃN���C�A���g��MAC�A�h���X

        timestamp : int or None, default blank
            ����̎��Ԃ̏����擾�������ꍇ�ɐݒ�
            �ݒ�l�̓G�|�b�N���ԁi�~���b�P�ʁj
            �ݒ肵�Ȃ��ꍇ�͍ŐV�̏����擾

        token : str, default None
            ���N�G�X�g�ɕK�v�ȃg�[�N�����O������w�肷��ꍇ�ɐݒ�
            �ݒ肵�Ȃ��ꍇ�A�C���X�^���X���ɕێ����Ă���g�[�N�����g�p����

        Returns
        -------
        _ : dict or None
            ���X�|���X�f�[�^
            ���N�G�X�g�Ɏ��s�����ꍇ��None

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
        �w�肵���N���C�A���g�ɔ������Ă���ُ킨��щ��P����擾����B

        Parameters
        ----------
        entity_type : str
            �ΏۃN���C�A���g����肷�邽�߂̃L�[
            "network_user_id" �܂��� "mac_address"

        entity_value : str
            �L�[�ɑ΂���p�����[�^
            ���[�UID�܂���MAC�A�h���X

        issue_category : str, default None
            �C�x���g�̃J�e�S�����i�荞�ޏꍇ�ɐݒ�

        token : str, default None
            ���N�G�X�g�ɕK�v�ȃg�[�N�����O������w�肷��ꍇ�ɐݒ�
            �ݒ肵�Ȃ��ꍇ�A�C���X�^���X���ɕێ����Ă���g�[�N�����g�p����

        Returns
        -------
        _ : dict or None
            ���X�|���X�f�[�^
            ���N�G�X�g�Ɏ��s�����ꍇ��None

        Raises
        ------
        """
        header = self.__create_header(append={"entity_type": entity_type,
                                              "entity_value": entity_value,
                                              "issueCategory": "" if issue_category is None else issue_category},
                                      token=token)
        data = self._send_http_request(self.get_client_enrichment_details_api, header=header)
        if data is None: return None

        # HTTP���X�|���X�� 200 �Ńf�[�^�ɃG���[�������Ă�p�^�[��������
        if "errorCode" in data:
            self.logger.error("Return error : [{}] {}".format(data["errorCode"], data["errorDescription"]))
            return None

        return data

    #===========================================================================
    # get_client_enrichment_by_mac
    #===========================================================================
    def get_client_enrichment_by_mac(self, mac, issue_category=None, token=None):
        """
        get_client_enrichment() �̃��b�p�[�֐��B
        """
        return self.get_client_enrichment("mac_address", mac, issue_category, token)

    #===========================================================================
    # get_client_enrichment_by_uid
    #===========================================================================
    def get_client_enrichment_by_uid(self, uid, issue_category=None, token=None):
        """
        get_client_enrichment() �̃��b�p�[�֐��B
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
        HTTP���N�G�X�g�w�b�_�𐶐�����B
        ���ʂňȉ��̃w�b�_����ݒ肷��B
            - Content-Type
            - Authorization

        Parameters
        ----------
        append : dict, default None
            �ǉ��Őݒ肷��w�b�_���̃}�b�v

        token : str, default None
            ���N�G�X�g�ɕK�v�ȃg�[�N�����O������w�肷��ꍇ�ɐݒ�
            �ݒ肵�Ȃ��ꍇ�A�C���X�^���X���ɕێ����Ă���g�[�N�����g�p����

        Returns
        -------
        ret : dict
            HTTP���N�G�X�g�w�b�_

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
        API�ւ̃��N�G�X�g���ɕK�v�ȃg�[�N�����擾����B
        �ŏ��ɂ��̃��\�b�h�����s���Ȃ��ƁA�ȍ~�̃��N�G�X�g�ɕK�v�ȃg�[�N���������Ȃ��B
        �g�[�N���̓C���X�^���X�����ɂ��L�^���邽�߁A�C���X�^���X��ێ�����ꍇ�̓g�[�N�����w�肷��K�v�͖����B

        Parameters
        ----------

        Returns
        -------
        _ : dict or None
            ���X�|���X�f�[�^
            ���N�G�X�g�Ɏ��s�����ꍇ��None

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
        �w�肵�����ԓ���Umbrella�̃A�N�e�B�r�e�B�̃��X�g���擾����B

        Parameters
        ----------
        org_id : str
            �Ώۑg�D��ID

        term_from : str or int
            ���Ԃ̊J�n����
            �^�C���X�^���v�̃V���A���l�ie.g. 14205322422�j�܂��͑��Ύ��Ԃ̕�����ie.g. -1days�j���w��

        term_to : str or int
            ���Ԃ̊J�n����
            �^�C���X�^���v�̃V���A���l�ie.g. 14205322422�j�܂��͑��Ύ��Ԃ̕�����ie.g. -1days�j���w��

        list_limit : int
            �擾����A�N�e�B�r�e�B�̍ő匏��

        act_type : str, default "all"
            �A�N�e�B�r�e�B�̎�ނŃt�B���^�[�������ꍇ�ɐݒ�
            �L���Ȓl�� dns/proxy/firewall/ip
            �ȗ��A�܂��͖����Ȓl���w�肳�ꂽ�ꍇ�A�t�B���^�[���Ȃ�

        act_category : str, default None
            �A�N�e�B�r�e�B�̃J�e�S���Ńt�B���^�[�������ꍇ�ɐݒ�
            �J�e�S��ID���J���}��؂�Ŏw�肷��

        ip : str, default None
            �N���C�A���g��IP�A�h���X�Ńt�B���^�[�������ꍇ�ɐݒ�

        token : str, default None
            ���N�G�X�g�ɕK�v�ȃg�[�N�����O������w�肷��ꍇ�ɐݒ�
            �ݒ肵�Ȃ��ꍇ�A�C���X�^���X���ɕێ����Ă���g�[�N�����g�p����

        Returns
        -------
        _ : list or None
            ���X�|���X�f�[�^
            ���N�G�X�g�Ɏ��s�����ꍇ��None

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

        # requests.get() �ł̓N�G��������̐������ɃJ���}���u%2C�v�ɕϊ�����̂ŁA�N�G���t��URL�𐶐����ēn���K�v����
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
        HTTP���N�G�X�g�w�b�_�𐶐�����B
        ���ʂňȉ��̃w�b�_����ݒ肷��B
            - Accept
            - Content-Type
            - Accept-Encoding
            - Authorization

        Parameters
        ----------
        append : dict, default None
            �ǉ��Őݒ肷��w�b�_���̃}�b�v

        Returns
        -------
        ret : dict
            HTTP���N�G�X�g�w�b�_

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
        �w�肵���z�X�g�R���s���[�^�̃��X�g���擾����B

        Parameters
        ----------
        list_limit : int
            ���X�g�̍ő匏��

        list_offset : int, default 0
            ���X�g�̎擾�J�n�ʒu

        ip : str, default None
            �z�X�g�R���s���[�^��IP�A�h���X�Ńt�B���^�[����ꍇ�ɐݒ�
            �������ȗ����邱�ƂŃA�h���X�т��w��ł���i���C���h�J�[�h�͕s�v�j

        Returns
        -------
        _ : list or None
            ���X�|���X�f�[�^
            ���N�G�X�g�Ɏ��s�����ꍇ��None

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
        �w�肵���C�x���g�̃��X�g���擾����B

        Parameters
        ----------
        list_limit : int
            ���X�g�̍ő匏��

        list_offset : int, default 0
            ���X�g�̎擾�J�n�ʒu

        connector_guid : str, default None
            Connector GUID�Ńt�B���^�[����ꍇ�ɐݒ�

        Returns
        -------
        _ : list or None
            ���X�|���X�f�[�^
            ���N�G�X�g�Ɏ��s�����ꍇ��None

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
        # �z��O�̃��N�G�X�g������Ă�����f�t�H���g�̃��b�Z�[�W��\������
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
            # �擪��1�䕪�����擾
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
            # �擪��1�䕪�����擾
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
        # �ڑ����؂�Ă��ăN���C�A���g�f�[�^�������c���Ă���ꍇ�AconnectionInfo �ɂ̓G���[��񂪓����Ă�
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

        # ���łɁAUmbrella��AMP4E�̏����擾����
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

    # TODO: �f���p�Ƃ��āA�ꕔ�̃t�B���^�����O�����͌Œ肷��
    org_id = "2067079"
    term_from = "-1days"
    term_to = "now"
    list_limit = 5
    act_category = "68,66,64"  # Malware, Phishing, C&C�̃J�e�S���Ńt�B���^�����O
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

    # TODO: �f���p�Ƃ��āA�ꕔ�̃t�B���^�����O�����͌Œ肷��
    list_limit = 5
    data = amp4e_driver.get_computers(list_limit, ip=ip)
    computers = data["data"]
    if len(computers) == 0:
        return [{"type": "text",
                 "value": "you do not have the AMP4E agent installed on your device. please contact IT department to install the agent."}]

    # �f�o�C�X��AMP4E���C���X�g�[���ς݂ł���΁A�C�x���g�����擾
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
    # DNAC�����ȏؖ������g���Ă��SSL�ؖ����̌��؂ŃG���[����������̂Ō��؂�OFF����
    # ���؂�OFF����� InsecureRequestWarning ���o��̂ŁA�������������
    urllib3.disable_warnings(InsecureRequestWarning)
    driver = DNACDriver(verify=False)
    umbrella_driver = UmbrellaDriver()
    amp4e_driver = AMP4EDriver()

    app.run(debug=True)
