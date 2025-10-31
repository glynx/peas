from twisted.internet import reactor, protocol, defer
from twisted.internet.ssl import ClientContextFactory
from twisted.python.failure import Failure
from twisted.web.client import Agent
from twisted.web.http_headers import Headers
from xml.dom.minidom import getDOMImplementation
import base64
import uuid
import sys
from io import BytesIO
from urllib.parse import urlencode, urlparse, urlunparse
from .dewbxml import wbxmlparser, wbxmlreader, wbxmldocument, wbxmlelement, wbxmlstring
from .activesync_producers import WBXMLProducer, FolderSyncProducer, SyncProducer, ProvisionProducer, ItemOperationsProducer
from ..http_logging import log_http_request, log_http_response

version = "1.0"
DEFAULT_USER_AGENT = "Outlook-iOS-Android/1.0"


def _idna_hostname(hostname):
    if not hostname:
        return hostname
    if isinstance(hostname, bytes):
        hostname = hostname.decode("utf-8")
    try:
        return hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return hostname


class DataReader(wbxmlreader):
    def __init__(self, data):
        self._wbxmlreader__bytes = BytesIO(data)

def convert_wbelem_to_dict(wbe):
    if isinstance(wbe, wbxmlelement):
        out_dict = {}
        k = wbe.name
        if len(wbe.children) == 1:
            v = convert_wbelem_to_dict(wbe.children[0])
        else:
            name_dupe = False
            child_names = []
            for child in wbe.children:
                if isinstance(child, wbxmlelement):
                    if child.name in child_names:
                        name_dupe = True
                        break
                    child_names.append(child.name)
            if not name_dupe:
                v = {}
                for child in wbe.children:
                    v.update(convert_wbelem_to_dict(child))
            else:
                v = []
                for child in wbe.children:
                    v.append(convert_wbelem_to_dict(child))
        out_dict[k] = v
    else:
        return str(wbe).strip()
    return out_dict


class WBXMLHandler(protocol.Protocol):
    def __init__(self, deferred, verbose=False):
        self.deferred = deferred
        self.d = b''
        self.verbose = verbose
    def dataReceived(self, data):
        self.d += data
    def connectionLost(self, reason):
        if self.verbose:
            print("FINISHED LOADING")
        if not self.d:
            # this is valid from sync command
            self.deferred.callback(None)
            return
        wb = wbxmlparser()
        doc = wb.parse(DataReader(self.d))
        res_dict = convert_wbelem_to_dict(doc.root)
        if self.verbose:
            print("Result:", res_dict)
        try:
            first_value = next(iter(res_dict.values()))
        except StopIteration:
            first_value = {}
        if isinstance(first_value, dict) and "Status" in first_value:
            err_status = int(first_value["Status"])
            if err_status != 1:
                self.deferred.errback(f"ActiveSync error {err_status}")
                return
        self.deferred.callback(res_dict)


class WebClientContextFactory(ClientContextFactory):
    def getContext(self, hostname, port):
        return ClientContextFactory.getContext(self)

class ActiveSync(object):
    def __init__(
        self,
        domain,
        username,
        pw,
        server,
        use_ssl,
        policy_key=0,
        server_version="14.0",
        device_type="iPhone",
        device_id=None,
        user_agent=None,
        verbose=False,
    ):
        self.use_ssl = use_ssl
        self.domain = domain
        self.username = username
        self.password = pw
        self.server = _idna_hostname(server)
        self.device_id = device_id
        self.server_version = server_version
        self.device_type = device_type
        self.policy_key = policy_key
        self.folder_data = {}
        self.verbose = verbose
        self.collection_data = {}
        clientContext = WebClientContextFactory()
        self.agent = Agent(reactor, clientContext)
        self.operation_queue = defer.DeferredQueue()
        self.queue_deferred = self.operation_queue.get()
        self.queue_deferred.addCallback(self.queue_full)
        ua = user_agent or DEFAULT_USER_AGENT
        self.user_agent = ua.encode("ascii")

    # Response processing

    def activesync_error(self, err):
        if self.verbose:
            print("ERROR", err)
        return Failure(exc_value=err, exc_type="ActiveSync")
    def options_response(self, resp):
        if resp.code != 200:
            return self.activesync_error("Response code %d"%resp.code)
        supported_commands = resp.headers.getRawHeaders("ms-asprotocolcommands")
        return supported_commands

    def wbxml_response(self, response):
        if response.code != 200:
            return self.activesync_error("Response code %d"%response.code)
        d = defer.Deferred()
        response.deliverBody(WBXMLHandler(d, self.verbose))
        return d

    def process_fetch(self, resp):
        if isinstance(resp["ItemOperations"]["Response"], list): # multifetch
            return resp["ItemOperations"]["Response"]
        else:
            return resp["ItemOperations"]["Response"]["Fetch"]

    def process_sync(self, resp, collection_id):
        if not resp:
            return self.collection_data[collection_id]["data"]
            
        sync_key = resp["Sync"]["Collections"]["Collection"]["SyncKey"]
        collection_id = resp["Sync"]["Collections"]["Collection"]["CollectionId"]
        
        assert collection_id != None
        if collection_id not in self.collection_data: # initial sync
            self.collection_data[collection_id] = {"key":sync_key}
            return self.sync(collection_id, sync_key)
        else:
            self.collection_data[collection_id]["key"] = sync_key
            if "data" not in self.collection_data[collection_id]:
                self.collection_data[collection_id]["data"] = {}
            if "Commands" in resp["Sync"]["Collections"]["Collection"]:

                commands = resp["Sync"]["Collections"]["Collection"]["Commands"]
                if isinstance(commands, dict):

                    for command, cmdinfo in commands.items():
                        if self.verbose:
                            print("PROCESS COMMAND:", command, cmdinfo)
                        if command == 'Add':
                            server_id = cmdinfo['ServerId']
                            self.collection_data[collection_id]['data'][server_id] = cmdinfo

                else:
                    # This seems to assume "commands" is a list but it was a dict when tested.
                    for command in resp["Sync"]["Collections"]["Collection"]["Commands"]:
                        if self.verbose:
                            print("PROCESS COMMAND", command)
                            print("all commands:", resp["Sync"]["Collections"]["Collection"]["Commands"])
                        if "Add" in command:
                            try:
                                server_id = command["Add"]["ServerId"]
                            except:
                                print("ERROR: Unexpected add format:", command["Add"])
                                continue
                            self.collection_data[collection_id]["data"][server_id] = command["Add"]
        
        if "MoreAvailable" in resp["Sync"]["Collections"]["Collection"]:
            if self.verbose:
                print("MORE AVAILABLE, syncing again")
            return self.sync(collection_id, sync_key)

        return self.collection_data[collection_id]["data"]

    def process_folder_sync(self, resp):
        if "folders" not in self.folder_data:
            self.folder_data["folders"] = {}
        self.folder_data["key"] = resp["FolderSync"]["SyncKey"]
        for change in resp["FolderSync"]["Changes"]:
            if "Add" in change:
                server_id = change["Add"]["ServerId"]
                self.folder_data["folders"][server_id] = change["Add"]
        return self.folder_data["folders"]

    def acknowledge_result(self, policyKey):
        if self.verbose:
            print("FINAL POLICY KEY", policyKey)
        self.policy_key = policyKey
        return True
    def process_policy_key(self, resp):
        try:
            policyKey = resp["Provision"]["Policies"]["Policy"]["PolicyKey"]
        except:
            raise Exception("ActiveSync","Retrieving policy key failed",sys.exc_info()[0])
        return policyKey


    # Request helpers

    def get_url(self):
        scheme = "http"
        if self.use_ssl:
            scheme = "https"
        return "%s://%s/Microsoft-Server-ActiveSync"%(scheme, self.server)
    def add_parameters(self, url, params):
        ps = list(urlparse(url))
        ps[4] = urlencode(params)
        return urlunparse(ps)
    def authorization_header(self):
        domain = (self.domain or "").lower()
        username = (self.username or "").lower()
        if domain:
            principal = f"{domain}\\{username}"
        else:
            principal = username
        creds = f"{principal}:{self.password}"
        encoded = base64.b64encode(creds.encode("utf-8")).decode("ascii")
        return f"Basic {encoded}"

    def _header_bytes(self, value):
        return value.encode("ascii") if isinstance(value, str) else value

    def _build_headers(self, include_content_type=False, include_protocol_headers=True, extra=None):
        headers = {
            b'User-Agent': [self.user_agent],
            b'Authorization': [self.authorization_header().encode("ascii")],
        }
        if include_protocol_headers:
            headers[b'MS-ASProtocolVersion'] = [self.server_version.encode("ascii")]
            headers[b'X-MS-PolicyKey'] = [str(self.policy_key).encode("ascii")]
        if include_content_type:
            headers[b'Content-Type'] = [b"application/vnd.ms-sync.wbxml"]
        if extra:
            for key, values in extra.items():
                headers[key] = [self._header_bytes(v) for v in values]
        return Headers(headers)

    def _request(self, method, url, headers=None, body=None):
        method_str = method.decode("ascii") if isinstance(method, (bytes, bytearray)) else method
        url_str = url.decode("ascii") if isinstance(url, (bytes, bytearray)) else url
        log_http_request(method_str, url_str, device_id=self.device_id, device_type=self.device_type, user=self.username)
        method_bytes = method_str.encode("ascii")
        url_bytes = url_str.encode("ascii")
        d = self.agent.request(method_bytes, url_bytes, headers, body)
        d.addCallback(self._log_response, method_str, url_str)
        return d

    def _log_response(self, response, method, url):
        header_map = {}
        raw_headers = getattr(response.headers, "_rawHeaders", {}) or {}
        for name, values in raw_headers.items():
            header_map[name] = values
        log_http_response(method, url, response.code, header_map)
        return response

    # Request queueing

    def queue_full(self, next_request):
        if self.verbose:
            print("Queue full", next_request)
        method = next_request[0]
        retd = next_request[-1]
        args = next_request[1:-2]
        kwargs = next_request[-2]
        d = method(*args, **kwargs)
        d.addCallback(self.request_finished, retd)
        d.addErrback(self.request_failed, retd)

    def request_finished(self, obj, return_deferred):
        if self.verbose:
            print("Request finished, resetting queue", obj, return_deferred)
        self.queue_deferred = self.operation_queue.get()
        self.queue_deferred.addCallback(self.queue_full)
        return_deferred.callback(obj)

    def request_failed(self, failure, return_deferred):
        if self.verbose:
            print("Request failed, resetting queue", failure, return_deferred)
        self.queue_deferred = self.operation_queue.get()
        self.queue_deferred.addCallback(self.queue_full)
        return_deferred.errback(failure)

    def add_operation(self, *operation_method_and_args, **kwargs):
        if self.verbose:
            print("Add operation", operation_method_and_args)
        ret_d = defer.Deferred()
        self.operation_queue.put(operation_method_and_args+(kwargs,ret_d,))
        return ret_d

    # Supported Requests

    def get_options(self):
        if self.verbose:
            print("Options, get URL:", self.get_url(), "Authorization", self.authorization_header())
        headers = self._build_headers(include_content_type=False, include_protocol_headers=False)
        d = self._request(
            b'OPTIONS',
            self.get_url(),
            headers,
            None)
        d.addCallback(self.options_response)
        d.addErrback(self.activesync_error)
        return d

    def acknowledge(self, policyKey):
        self.policy_key = policyKey
        prov_url = self.add_parameters(self.get_url(), {"Cmd":"Provision", "User":self.username, "DeviceId":self.device_id, "DeviceType":self.device_type})
        headers = self._build_headers(include_content_type=True)
        d = self._request(
            b'POST',
            prov_url,
            headers,
            ProvisionProducer(policyKey, verbose=self.verbose))
        d.addCallback(self.wbxml_response)
        d.addCallback(self.process_policy_key)
        d.addCallback(self.acknowledge_result)
        d.addErrback(self.activesync_error)
        return d    

    def provision(self):
        prov_url = self.add_parameters(self.get_url(), {"Cmd":"Provision", "User":self.username, "DeviceId":self.device_id, "DeviceType":self.device_type})
        headers = self._build_headers(include_content_type=True)
        d = self._request(
            b'POST',
            prov_url,
            headers,
            ProvisionProducer(verbose=self.verbose))
        d.addCallback(self.wbxml_response)
        d.addCallback(self.process_policy_key)
        d.addCallback(self.acknowledge)
        d.addErrback(self.activesync_error)
        return d    

    def folder_sync(self, sync_key=0):
        if sync_key == 0 and "key" in self.folder_data:
            sync_key = self.folder_data["key"]
        sync_url = self.add_parameters(self.get_url(), {"Cmd":"FolderSync", "User":self.username, "DeviceId":self.device_id, "DeviceType":self.device_type})
        headers = self._build_headers(include_content_type=True)
        d = self._request(
            b'POST',
            sync_url,
            headers,
            FolderSyncProducer(sync_key, verbose=self.verbose))
        d.addCallback(self.wbxml_response)
        d.addCallback(self.process_folder_sync)
        d.addErrback(self.activesync_error)
        return d

    def sync(self, collectionId, sync_key=0, get_body=False):
        if sync_key == 0 and collectionId in self.collection_data:
            sync_key = self.collection_data[collectionId]["key"]

        sync_url = self.add_parameters(self.get_url(), {"Cmd":"Sync", "User":self.username, "DeviceId":self.device_id, "DeviceType":self.device_type})
        headers = self._build_headers(include_content_type=True)
        d = self._request(
            b'POST',
            sync_url,
            headers,
            SyncProducer(collectionId, sync_key, get_body, verbose=self.verbose))
        d.addCallback(self.wbxml_response)
        d.addCallback(self.process_sync, collectionId)
        d.addErrback(self.activesync_error)
        return d

    def fetch(self, collectionId, serverId, fetchType, mimeSupport=0):
        fetch_url = self.add_parameters(self.get_url(), {"Cmd":"ItemOperations", "User":self.username, "DeviceId":self.device_id, "DeviceType":self.device_type})
        headers = self._build_headers(include_content_type=True)
        d = self._request(
            b'POST',
            fetch_url,
            headers,
            ItemOperationsProducer("Fetch", collectionId, serverId, fetchType, mimeSupport, store="Mailbox", verbose=self.verbose))
        d.addCallback(self.wbxml_response)
        d.addCallback(self.process_fetch)
        d.addErrback(self.activesync_error)
        return d

    def fetch_link(self, linkId):
        fetch_url = self.add_parameters(self.get_url(), {"Cmd":"ItemOperations", "User":self.username, "DeviceId":self.device_id, "DeviceType":self.device_type})
        headers = self._build_headers(include_content_type=True)
        d = self._request(
            b'POST',
            fetch_url,
            headers,
            ItemOperationsProducer("Fetch", None, linkId, None, None, store="DocumentLibrary", verbose=self.verbose))
        d.addCallback(self.wbxml_response)
        d.addCallback(self.process_fetch)
        d.addErrback(self.activesync_error)
        return d
