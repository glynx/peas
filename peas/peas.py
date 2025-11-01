from . import py_eas_helper
from . import py_activesync_helper


PY_ACTIVE_SYNC = 1
PY_EAS_CLIENT = 2


class Peas:

    def __init__(self):
        self._backend = PY_ACTIVE_SYNC
        self._creds = {}

    def set_backend(self, backend_id):
        """Set which backend library to use."""

        assert(backend_id in [PY_ACTIVE_SYNC, PY_EAS_CLIENT])

        self._backend = backend_id

    def set_creds(self, creds):
        """Configure which exchange server, credentials and other settings to use."""
        self._creds.update(creds)

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

    def provision_device(self):
        assert self._backend == PY_ACTIVE_SYNC
        return py_activesync_helper.provision_device(self._creds)

    def list_folders(self):
        assert self._backend == PY_ACTIVE_SYNC
        return py_activesync_helper.list_folders(self._creds)

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
