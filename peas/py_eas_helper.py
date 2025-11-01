__author__ = 'Adam Rutherford'

from twisted.internet import reactor

from .eas_client import activesync
import uuid


def body_result(result, emails, num_emails):
    emails.append(result['Properties']['Body'])
    # Stop after receiving final email.
    if len(emails) == num_emails:
        reactor.stop()


def sync_result(result, fid, as_client, emails):
    assert hasattr(result, 'keys')
    num_emails = len(result)
    for fetch_id in result:
        as_client.add_operation(as_client.fetch, collectionId=fid, serverId=fetch_id,
            fetchType=4, mimeSupport=2).addBoth(body_result, emails, num_emails)


def fsync_result(result, as_client, emails):
    for (fid, finfo) in result.items():
        if finfo['DisplayName'] == 'Inbox':
            as_client.add_operation(as_client.sync, fid).addBoth(sync_result, fid, as_client, emails)
            break


def prov_result(success, as_client, emails):
    if success:
        as_client.add_operation(as_client.folder_sync).addBoth(fsync_result, as_client, emails)
    else:
        reactor.stop()


def extract_emails(creds):
    emails = []
    as_client = activesync.ActiveSync(
        domain='',  # not needed because username with domain\username works as well
        username=creds['user'],
        pw=creds['password'],
        server=creds['server'],
        use_ssl=True,
        device_id=creds['device_id'],
        device_type=creds['device_type'],
        user_agent=creds['user_agent'],
        verbose=False
    )
    as_client.add_operation(as_client.provision).addBoth(prov_result, as_client, emails)
    reactor.run()
    return emails
