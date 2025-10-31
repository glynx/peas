__author__ = 'Adam Rutherford'

import uuid

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from . import py_eas_helper
from . import py_activesync_helper
from .http_logging import log_http_request, log_http_response


PY_ACTIVE_SYNC = 1
PY_EAS_CLIENT = 2


def _idna_hostname(host):
    if not host:
        return host
    if isinstance(host, bytes):
        host = host.decode('utf-8')
    try:
        return host.encode('idna').decode('ascii')
    except UnicodeError:
        return host


class Peas:

    def __init__(self):
        self._backend = PY_ACTIVE_SYNC

        self._creds = {
            'server': None,
            'user': None,
            'password': None,
            'domain': None,     # This could be optional.
            'device_id': None,  # This could be optional.
            'device_type': None,
            'user_agent': None,
            'folder': None,
        }

        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    def set_backend(self, backend_id):
        """Set which backend library to use."""

        assert(backend_id in [PY_ACTIVE_SYNC, PY_EAS_CLIENT])

        self._backend = backend_id

    def set_creds(self, creds):
        """Configure which exchange server, credentials and other settings to use."""
        processed = dict(creds)
        server = processed.get('server')
        if isinstance(server, (str, bytes)):
            processed['server'] = _idna_hostname(server)
        self._creds.update(processed)
        if self._creds.get('device_id') is None:
            self._creds['device_id'] = uuid.uuid4().hex[:32]
        if self._creds.get('device_type') is None:
            self._creds['device_type'] = 'iPhone'
        if self._creds.get('user_agent') is None:
            self._creds['user_agent'] = 'Outlook-iOS-Android/1.0'

    def extract_emails_py_active_sync(self):
        emails = py_activesync_helper.extract_emails(self._creds)
        return emails

    def extract_emails_py_eas_client(self):

        emails = py_eas_helper.extract_emails(self._creds)
        return emails

    def extract_emails(self):
        """Retrieve and return emails."""

        if self._backend == PY_ACTIVE_SYNC:
            return self.extract_emails_py_active_sync()

        if self._backend == PY_EAS_CLIENT:
            return self.extract_emails_py_eas_client()

    # TODO: This returns a response object. Make it a public method when it returns something more generic.
    def _get_options(self):

        assert self._backend == PY_ACTIVE_SYNC

        as_conn = py_activesync_helper.ASHTTPConnector(self._creds['server'])  #e.g. "as.myserver.com"
        as_conn.set_credential(self._creds['user'], self._creds['password'])
        return as_conn.get_options()

    def check_auth(self):
        """Perform an OPTIONS request which will fail if the credentials are incorrect.

        401 Unauthorized is returned if the credentials are incorrect but other status codes may be possible,
            leading to false negatives.
        """

        resp = self._get_options()
        return resp.status == 200

    def disable_certificate_verification(self):

        assert self._backend == PY_ACTIVE_SYNC

        py_activesync_helper.disable_certificate_verification()

    def list_folders(self):

        assert self._backend == PY_ACTIVE_SYNC

        return py_activesync_helper.list_folders(self._creds)

    def get_server_headers(self):
        """Get the ActiveSync web server headers."""

        sess = requests.Session()

        url = 'https://' + self._creds['server'] + '/Microsoft-Server-ActiveSync'
        user_agent = self._creds.get('user_agent') or "Outlook-iOS-Android/1.0"
        sess.headers.update({"User-Agent": user_agent})
        log_http_request(
            "GET",
            url,
            user=self._creds.get('user'),
            device_id=self._creds.get('device_id'),
            device_type=self._creds.get('device_type'),
        )

        # TODO: Allow user to specify if SSL is verified.
        resp = sess.get(url, verify=False)
        log_http_response("GET", url, resp.status_code, resp.headers)

        return resp.headers

    def get_unc_listing(self, unc_path):
        """Retrieve and return a file listing of the given UNC path."""

        assert self._backend == PY_ACTIVE_SYNC

        # Use alternative credentials for SMB if supplied.
        user = self._creds.get('smb_user', self._creds['user'])
        password = self._creds.get('smb_password', self._creds['password'])

        # Enable the option to send no credentials at all.
        if user == '<none>':
            user = None
        if password == '<none>':
            password = None

        results = py_activesync_helper.get_unc_listing(self._creds, unc_path,
            username=user, password=password)

        return results

    def get_unc_file(self, unc_path):
        """Return the file data of the file at the given UNC path."""

        assert self._backend == PY_ACTIVE_SYNC

        # Use alternative credentials for SMB if supplied.
        user = self._creds.get('smb_user', self._creds['user'])
        password = self._creds.get('smb_password', self._creds['password'])

        # Enable the option to send no credentials at all.
        if user == '<none>':
            user = None
        if password == '<none>':
            password = None

        data = py_activesync_helper.get_unc_file(self._creds, unc_path,
            username=user, password=password)

        return data


def show_banner():
    print('''\033[0;37m\
 _ __   ___  __ _ ___
| '_ \ / _ \/ _' / __|
| |_) |  __/ (_| \__ \\
| .__/ \___|\__._|___/
|_| \033[1;37m- Probe ActiveSync
\033[0m''')


def main():
    show_banner()


if __name__ == '__main__':
    main()
