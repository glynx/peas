########################################################################
#  Copyright (C) 2013 Sol Birnbaum
# 
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
# 
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
# 
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA  02110-1301, USA.
########################################################################

from http import client as http_client
import base64
from ...http_logging import log_http_request, log_http_response


def _idna_hostname(host):
    if not host:
        return host
    if isinstance(host, bytes):
        host = host.decode("utf-8")
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host

class ASHTTPConnector(object):
    """ActiveSync HTTP object"""
    DEFAULT_DEVICE_ID = "2095f3b9f442a32220d4d54e641bd4aa"
    DEFAULT_DEVICE_TYPE = "iPhone"
    USER_AGENT = "Outlook-iOS-Android/1.0"
    POST_URL_TEMPLATE = "/Microsoft-Server-ActiveSync?Cmd=%s&User=%s&DeviceId=%s&DeviceType=%s"
    POST_GETATTACHMENT_URL_TEMPLATE = "/Microsoft-Server-ActiveSync?Cmd=%s&AttachmentName=%s&User=%s&DeviceId=%s&DeviceType=%s"

    def __init__(self, server, port=443, ssl=True, device_id=None, device_type=None, user_agent=None):
        self.server = _idna_hostname(server)
        self.port = port
        self.ssl = ssl
        self.policykey = 0
        self.device_id = device_id or self.DEFAULT_DEVICE_ID
        self.device_type = device_type or self.DEFAULT_DEVICE_TYPE
        ua = user_agent or self.USER_AGENT
        self.headers = {
                        "Content-Type": "application/vnd.ms-sync.wbxml",
                        "User-Agent" : ua,
                        "MS-ASProtocolVersion" : "14.1",
                        "Accept-Language" : "en_us"
                        }
        return

    def set_credential(self, username, password):
        self.username = username
        credentials = f"{username}:{password}".encode("utf-8")
        self.credential = base64.b64encode(credentials).decode("ascii")
        self.headers.update({"Authorization" : "Basic " + self.credential})

    def do_post(self, url, body, headers, redirected=False):
        scheme = "https" if self.ssl else "http"
        default_port = 443 if self.ssl else 80
        host = self.server if self.port == default_port else f"{self.server}:{self.port}"
        full_url = f"{scheme}://{host}{url}"
        log_http_request("POST", full_url, user=getattr(self, "username", None), device_id=self.device_id, device_type=self.device_type)
        if self.ssl:
            conn = http_client.HTTPSConnection(self.server, self.port)
            conn.request("POST", url, body, headers)
        else:
            conn = http_client.HTTPConnection(self.server, self.port)
            conn.request("POST", url, body, headers)
        res = conn.getresponse()
        header_map = dict(res.getheaders())
        log_http_response("POST", full_url, res.status, header_map)
        if res.status == 451:
            self.server = _idna_hostname(res.getheader("X-MS-Location").split()[2])
            if not redirected:
                return self.do_post(url, body, headers, False)
            else:
                raise Exception("Redirect loop encountered. Stopping request.")
        else:
            return res


    def post(self, cmd, body):
        url = self.POST_URL_TEMPLATE % (cmd, self.username, self.device_id, self.device_type)
        res = self.do_post(url, body, self.headers)
        #print res.status, res.reason, res.getheaders()
        return res.read()

    def fetch_multipart(self, body, filename="fetched_file.tmp"):
        """http://msdn.microsoft.com/en-us/library/ee159875(v=exchg.80).aspx"""
        headers = self.headers
        headers.update({"MS-ASAcceptMultiPart":"T"})
        url = self.POST_URL_TEMPLATE % ("ItemOperations", self.username, self.device_id, self.device_type)
        res = self.do_post(url, body, headers)
        if res.getheaders()["Content-Type"] == "application/vnd.ms-sync.multipart":
            PartCount = int(res.read(4))
            PartMetaData = []
            for partindex in range(0, PartCount):
                PartMetaData.append((int(res.read(4))), (int(res.read(4))))
            wbxml_part = res.read(PartMetaData[0][1])
            fetched_file = open(filename, "wb")
            for partindex in range(1, PartCount):
                fetched_file.write(res.read(PartMetaData[0][partindex]))
            fetched_file.close()
            return wbxml, filename
        else:
            raise TypeError("Client requested MultiPart response, but server responsed with inline.")

    def get_attachment(self, attachment_name): #attachment_name = DisplayName of attachment from an MSASAIRS.Attachment object
        url = self.POST_GETATTACHMENT_URL_TEMPLATE  % ("GetAttachment", attachment_name, self.username, self.device_id, self.device_type)
        res = self.do_post(url, "", self.headers)
        try:
            content_type = res.getheader("Content-Type")
        except:
            content_type = "text/plain"
        res.status
        return res.read(), res.status, content_type

    def get_options(self):
        scheme = "https" if self.ssl else "http"
        default_port = 443 if self.ssl else 80
        host = self.server if self.port == default_port else f"{self.server}:{self.port}"
        path = "/Microsoft-Server-ActiveSync"
        full_url = f"{scheme}://{host}{path}"
        log_http_request("OPTIONS", full_url, user=getattr(self, "username", None), device_id=self.device_id, device_type=self.device_type)
        if self.ssl:
            conn = http_client.HTTPSConnection(self.server, self.port)
        else:
            conn = http_client.HTTPConnection(self.server, self.port)
        conn.request("OPTIONS", path, None, self.headers)
        res = conn.getresponse()
        log_http_response("OPTIONS", full_url, res.status, dict(res.getheaders()))
        return res

    def options(self):
        res = self.get_options()
        if res.status == 200:
            self._server_protocol_versions = res.getheader("ms-asprotocolversions")
            self._server_protocol_commands = res.getheader("ms-asprotocolcommands")
            self._server_version = res.getheader("ms-server-activesync")
            return True
        else:
            print("Connection Error!:")
            print(res.status, res.reason)
            for header in res.getheaders():
                print(f"{header[0]}:", header[1])
            return False

    def get_policykey(self):
        return self.policykey

    def set_policykey(self, policykey):
        self.policykey = policykey
        self.headers.update({ "X-MS-PolicyKey" : self.policykey })
