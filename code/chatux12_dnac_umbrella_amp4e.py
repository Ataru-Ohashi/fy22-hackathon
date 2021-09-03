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
    JSONファイルをロードする。
    ファイルが無い場合は空のdictを返却する。

    Parameters
    ----------
    file_path : str
        JSONファイルパス

    Returns
    -------
    _ : dict
        パラメータマップ

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
    文字列をBase64でエンコードする。
    内部的には、一旦byte列に変換してエンコードしてからstrにデコードしている。

    Parameters
    ----------
    inputStr : str
        エンコード対象文字列

    Returns
    -------
    _ : str
        エンコード済み文字列

    Raises
    ------
    """
    return base64.b64encode(inputStr.encode()).decode()


#===============================================================================
# CiscoAPIDriver
#===============================================================================
class CiscoAPIDriver:
    """
    各APIドライバーのスーパークラス
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
        HTTPリクエストの送信と、HTTPレスポンスの受信を行う共通処理。
        リターンコードの確認まで行い、データの確認は呼び元で行う。

        Parameters
        ----------
        api : tuple
            使用するHTTPリクエストとリクエスト先URLのタプル

        header : dict, default None
            リクエストヘッダー

        payload : dict, default None
            リクエストに添付するクエリデータ
            GETならURLに接続し、POSTならBodyに組み込む

        return_all : bool, default False
            レスポンスデータ全体を返却する場合に True を設定
            デフォルトではディクショナリ形式に変換して返却する

        Returns
        -------
        ret : dict or Response or None
            レスポンスデータを全体または変換後の形式で返却
            リクエストに失敗した場合はNone

        Raises
        ------
        """
        self.logger.debug("{} START".format(sys._getframe().f_code.co_name))
        ret = None
        try_limit = 3  # とりあえず3回試行できるようにしておく
        retry_interval = 5
        for _ in range(1, try_limit, 1):
            try:
                self.logger.debug("Request URL: [{}] {}".format(api[0], api[1]))

                # リクエスト送信
                if api[0] == "GET":
                    res = requests.get(api[1], headers=header, params=payload, verify=self.verify)
                elif api[0] == "POST":
                    res = requests.post(api[1], headers=header, data=json.dumps(payload), verify=self.verify)

                # リターンコードが 200 台でない場合に例外を送出
                res.raise_for_status()

                status_code = res.status_code
                self.logger.debug(f"Return Code: {status_code}")
                ret = res if return_all else res.json()
                break

            # 接続エラー系は再実行
            except (requests.exceptions.ProxyError, requests.exceptions.ConnectionError) as e:
                self.logger.exception(f"HTTP connection error: {e}")
                sleep(retry_interval)

            # 上記以外の例外は異常終了
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
        パスにプロトコルとFQDNを接続し、HTTPリクエスト用URLを生成する。

        Parameters
        ----------
        api_path : str
            APIパス
            先頭はスラッシュ "/" であること

        Returns
        -------
        _ : str
            HTTPリクエストURL
            パスがNone（設定が無い）の場合はNoneを返却する

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
        HTTPリクエストヘッダを生成する。
        共通で以下のヘッダ情報を設定する。
            - Content-Type
            - Accept
            - x-auth-token

        Parameters
        ----------
        append : dict, default None
            追加で設定するヘッダ情報のマップ

        token : str, default None
            リクエストに必要なトークンを外部から指定する場合に設定
            設定しない場合、インスタンス内に保持しているトークンを使用する

        Returns
        -------
        ret : dict
            HTTPリクエストヘッダ

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
        APIへのリクエスト時に必要なトークンを取得する。
        最初にこのメソッドを実行しないと、以降のリクエストに必要なトークンが得られない。
        トークンはインスタンス内部にも記録するため、インスタンスを保持する場合はトークンを指定する必要は無い。

        Parameters
        ----------

        Returns
        -------
        _ : str or None
            トークンを返却
            リクエストに失敗した場合はNone

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
        指定したデバイスのリストを取得する。
        条件を指定しない場合、DNACに登録されている全てのデバイスを取得する。

        Parameters
        ----------
        hostname : str, default None
            デバイスのホスト名を指定する場合に設定
            ワイルドカード使用可

        token : str, default None
            リクエストに必要なトークンを外部から指定する場合に設定
            設定しない場合、インスタンス内に保持しているトークンを使用する

        Returns
        -------
        _ : list or None
            デバイスのリストを返却
            リクエストに失敗した場合はNone

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
        指定したデバイスのConfigを暗号化Zip形式でエクスポートする。
        Configはクリアテキスト形式で出力され、パスワード等の文字列はマスクされない。
        暗号化Zipのパスワードは「[ユーザ名]：[パスワード]」となる。
        ※ここではエクスポート処理をキックするだけで、ダウンロードはできない。

        Parameters
        ----------
        ids : list
            Config出力対象となるデバイスのIDリスト

        token : str, default None
            リクエストに必要なトークンを外部から指定する場合に設定
            設定しない場合、インスタンス内に保持しているトークンを使用する

        Returns
        -------
        _ : list or None
            エクスポートプロセスのタスクIDを返却
            リクエストに失敗した場合はNone

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
        指定したタスクの状態を取得する。

        Parameters
        ----------
        task_id : str
            対象タスクのID

        token : str, default None
            リクエストに必要なトークンを外部から指定する場合に設定
            設定しない場合、インスタンス内に保持しているトークンを使用する

        Returns
        -------
        _ : list or None
            レスポンスデータ
            リクエストに失敗した場合はNone

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
        指定したファイルをダウンロードする。
        ファイルIDまたは追加URLのいずれかを指定すること。
        両方を指定した場合はファイルIDを優先する。
        両方を指定しない場合はFalseを返却する。

        Parameters
        ----------
        file_id : str, default None
            対象ファイルのID

        additional_status_url : str, default None
            ファイル生成タスクから入手したダウンロードURL

        token : str, default None
            リクエストに必要なトークンを外部から指定する場合に設定
            設定しない場合、インスタンス内に保持しているトークンを使用する

        Returns
        -------
        _ : bool
            ダウンロードに成功した場合はTrue
            それ以外の場合はFalse

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

        # レスポンスヘッダからファイル名を取得
        content_disposition = res.headers["Content-Disposition"]
        filename_attribute = "filename="
        filename = content_disposition[content_disposition.find(filename_attribute) + len(filename_attribute):]
        filename = filename.replace("\"", "")

        # バイナリデータとしてファイル出力
        with open(filename, "wb") as f:
            f.write(res.content)

        return True

    #===========================================================================
    # get_client
    #===========================================================================
    def get_client(self, mac, timestamp=None, token=None):
        """
        指定したクライアントの詳細情報を取得する。

        Parameters
        ----------
        mac : str
            対象クライアントのMACアドレス

        timestamp : int or None, default blank
            特定の時間の情報を取得したい場合に設定
            設定値はエポック時間（ミリ秒単位）
            設定しない場合は最新の情報を取得

        token : str, default None
            リクエストに必要なトークンを外部から指定する場合に設定
            設定しない場合、インスタンス内に保持しているトークンを使用する

        Returns
        -------
        _ : dict or None
            レスポンスデータ
            リクエストに失敗した場合はNone

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
        指定したクライアントに発生している異常および改善策を取得する。

        Parameters
        ----------
        entity_type : str
            対象クライアントを特定するためのキー
            "network_user_id" または "mac_address"

        entity_value : str
            キーに対するパラメータ
            ユーザIDまたはMACアドレス

        issue_category : str, default None
            イベントのカテゴリを絞り込む場合に設定

        token : str, default None
            リクエストに必要なトークンを外部から指定する場合に設定
            設定しない場合、インスタンス内に保持しているトークンを使用する

        Returns
        -------
        _ : dict or None
            レスポンスデータ
            リクエストに失敗した場合はNone

        Raises
        ------
        """
        header = self.__create_header(append={"entity_type": entity_type,
                                              "entity_value": entity_value,
                                              "issueCategory": "" if issue_category is None else issue_category},
                                      token=token)
        data = self._send_http_request(self.get_client_enrichment_details_api, header=header)
        if data is None: return None

        # HTTPレスポンスは 200 でデータにエラーが入ってるパターンがある
        if "errorCode" in data:
            self.logger.error("Return error : [{}] {}".format(data["errorCode"], data["errorDescription"]))
            return None

        return data

    #===========================================================================
    # get_client_enrichment_by_mac
    #===========================================================================
    def get_client_enrichment_by_mac(self, mac, issue_category=None, token=None):
        """
        get_client_enrichment() のラッパー関数。
        """
        return self.get_client_enrichment("mac_address", mac, issue_category, token)

    #===========================================================================
    # get_client_enrichment_by_uid
    #===========================================================================
    def get_client_enrichment_by_uid(self, uid, issue_category=None, token=None):
        """
        get_client_enrichment() のラッパー関数。
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
        HTTPリクエストヘッダを生成する。
        共通で以下のヘッダ情報を設定する。
            - Content-Type
            - Authorization

        Parameters
        ----------
        append : dict, default None
            追加で設定するヘッダ情報のマップ

        token : str, default None
            リクエストに必要なトークンを外部から指定する場合に設定
            設定しない場合、インスタンス内に保持しているトークンを使用する

        Returns
        -------
        ret : dict
            HTTPリクエストヘッダ

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
        APIへのリクエスト時に必要なトークンを取得する。
        最初にこのメソッドを実行しないと、以降のリクエストに必要なトークンが得られない。
        トークンはインスタンス内部にも記録するため、インスタンスを保持する場合はトークンを指定する必要は無い。

        Parameters
        ----------

        Returns
        -------
        _ : dict or None
            レスポンスデータ
            リクエストに失敗した場合はNone

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
        指定した期間内のUmbrellaのアクティビティのリストを取得する。

        Parameters
        ----------
        org_id : str
            対象組織のID

        term_from : str or int
            期間の開始時間
            タイムスタンプのシリアル値（e.g. 14205322422）または相対時間の文字列（e.g. -1days）を指定

        term_to : str or int
            期間の開始時間
            タイムスタンプのシリアル値（e.g. 14205322422）または相対時間の文字列（e.g. -1days）を指定

        list_limit : int
            取得するアクティビティの最大件数

        act_type : str, default "all"
            アクティビティの種類でフィルターしたい場合に設定
            有効な値は dns/proxy/firewall/ip
            省略、または無効な値が指定された場合、フィルターしない

        act_category : str, default None
            アクティビティのカテゴリでフィルターしたい場合に設定
            カテゴリIDをカンマ区切りで指定する

        ip : str, default None
            クライアントのIPアドレスでフィルターしたい場合に設定

        token : str, default None
            リクエストに必要なトークンを外部から指定する場合に設定
            設定しない場合、インスタンス内に保持しているトークンを使用する

        Returns
        -------
        _ : list or None
            レスポンスデータ
            リクエストに失敗した場合はNone

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

        # requests.get() ではクエリ文字列の生成時にカンマを「%2C」に変換するので、クエリ付きURLを生成して渡す必要あり
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
        HTTPリクエストヘッダを生成する。
        共通で以下のヘッダ情報を設定する。
            - Accept
            - Content-Type
            - Accept-Encoding
            - Authorization

        Parameters
        ----------
        append : dict, default None
            追加で設定するヘッダ情報のマップ

        Returns
        -------
        ret : dict
            HTTPリクエストヘッダ

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
        指定したホストコンピュータのリストを取得する。

        Parameters
        ----------
        list_limit : int
            リストの最大件数

        list_offset : int, default 0
            リストの取得開始位置

        ip : str, default None
            ホストコンピュータのIPアドレスでフィルターする場合に設定
            末尾を省略することでアドレス帯を指定できる（ワイルドカードは不要）

        Returns
        -------
        _ : list or None
            レスポンスデータ
            リクエストに失敗した場合はNone

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
        指定したイベントのリストを取得する。

        Parameters
        ----------
        list_limit : int
            リストの最大件数

        list_offset : int, default 0
            リストの取得開始位置

        connector_guid : str, default None
            Connector GUIDでフィルターする場合に設定

        Returns
        -------
        _ : list or None
            レスポンスデータ
            リクエストに失敗した場合はNone

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
        # 想定外のリクエストが流れてきたらデフォルトのメッセージを表示する
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
            # 先頭の1台分だけ取得
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
            # 先頭の1台分だけ取得
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
        # 接続が切れていてクライアントデータだけが残っている場合、connectionInfo にはエラー情報が入ってる
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

        # ついでに、UmbrellaとAMP4Eの情報も取得する
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

    # TODO: デモ用として、一部のフィルタリング条件は固定する
    org_id = "2067079"
    term_from = "-1days"
    term_to = "now"
    list_limit = 5
    act_category = "68,66,64"  # Malware, Phishing, C&Cのカテゴリでフィルタリング
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

    # TODO: デモ用として、一部のフィルタリング条件は固定する
    list_limit = 5
    data = amp4e_driver.get_computers(list_limit, ip=ip)
    computers = data["data"]
    if len(computers) == 0:
        return [{"type": "text",
                 "value": "you do not have the AMP4E agent installed on your device. please contact IT department to install the agent."}]

    # デバイスにAMP4Eがインストール済みであれば、イベント情報を取得
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
    # DNACが自己証明書を使ってるとSSL証明書の検証でエラーが発生するので検証をOFFする
    # 検証をOFFすると InsecureRequestWarning が出るので、それも無視する
    urllib3.disable_warnings(InsecureRequestWarning)
    driver = DNACDriver(verify=False)
    umbrella_driver = UmbrellaDriver()
    amp4e_driver = AMP4EDriver()

    app.run(debug=True)

