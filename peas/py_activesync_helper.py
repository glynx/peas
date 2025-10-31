########################################################################
# Modified 2016 from code Copyright (C) 2013 Sol Birnbaum
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
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
########################################################################\

import ssl
import re
import uuid
from pathlib import Path

# https://docs.python.org/2/library/xml.html#xml-vulnerabilities
from lxml import etree as ElementTree

from .pyActiveSync.utils.as_code_pages import as_code_pages
from .pyActiveSync.utils.wbxml import wbxml_parser
from .pyActiveSync.client.storage import storage

from .pyActiveSync.client.FolderSync import FolderSync
from .pyActiveSync.client.Sync import Sync
from .pyActiveSync.client.GetItemEstimate import GetItemEstimate
from .pyActiveSync.client.Provision import Provision
from .pyActiveSync.client.Search import Search
from .pyActiveSync.client.ItemOperations import ItemOperations

from .pyActiveSync.objects.MSASHTTP import ASHTTPConnector
from .pyActiveSync.objects.MSASCMD import as_status
from .pyActiveSync.objects.MSASAIRS import airsync_FilterType, airsync_Conflict, airsync_MIMETruncation, \
    airsync_MIMESupport, \
    airsync_Class, airsyncbase_Type


# Create WBXML parser instance.
parser = wbxml_parser(*as_code_pages.build_as_code_pages())

LAST_GETITEMESTIMATE = []


def _ensure_device_profile(creds):
    if not creds.get('device_id'):
        creds['device_id'] = uuid.uuid4().hex[:32]
    if not creds.get('device_type'):
        creds['device_type'] = ASHTTPConnector.DEFAULT_DEVICE_TYPE
    if not creds.get('user_agent'):
        creds['user_agent'] = ASHTTPConnector.USER_AGENT
    if not creds.get('device_os'):
        creds['device_os'] = 'OutlookBasicAuth'
    if not creds.get('device_imei'):
        creds['device_imei'] = ASHTTPConnector.DEFAULT_DEVICE_ID
    return (
        creds['device_id'],
        creds['device_type'],
        creds['user_agent'],
        creds['device_os'],
        creds['device_imei'],
    )


def _sanitize(value, default="default"):
    if not value:
        return default
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(value))


def _get_db_path(creds):
    server_component = _sanitize(creds.get("server"), "server")
    user_component = _sanitize(creds.get("user"), "account")
    base_dir = Path.cwd() / "pyas_cache" / server_component
    base_dir.mkdir(parents=True, exist_ok=True)
    return str(base_dir / f"{user_component}.asdb")


def _parse_for_emails(res, emails):

    data = str(res)
    if not data.strip():
        return

    try:
        payload = data.encode("utf-8")
    except UnicodeError:
        payload = data

    etparser = ElementTree.XMLParser(recover=True)
    try:
        tree = ElementTree.fromstring(payload, etparser)
    except (ElementTree.XMLSyntaxError, ValueError):
        return
    if tree is None:
        return

    for item in tree.iter('{airsync:}ApplicationData'):
        # Ask lxml to hand back a Python str so downstream code always deals with text.
        s = ElementTree.tostring(item, encoding='unicode')
        emails.append(s)


def as_request(as_conn, cmd, wapxml_req):
    #print "\r\n%s Request:" % cmd
    #print wapxml_req
    res = as_conn.post(cmd, parser.encode(wapxml_req))
    wapxml_res = parser.decode(res)
    #print "\r\n%s Response:" % cmd
    #print wapxml_res
    return wapxml_res


#Provision functions
def do_apply_eas_policies(policies):
    for policy in policies:
        #print "Virtually applying %s = %s" % (policy, policies[policy])
        pass
    return True


def do_provision(as_conn, device_info, db_path):
    provision_xmldoc_req = Provision.build("0", device_info)
    as_conn.set_policykey("0")
    provision_xmldoc_res = as_request(as_conn, "Provision", provision_xmldoc_req)
    status, policystatus, policykey, policytype, policydict, settings_status = Provision.parse(provision_xmldoc_res)
    as_conn.set_policykey(policykey)
    storage.update_keyvalue("X-MS-PolicyKey", policykey, path=db_path)
    storage.update_keyvalue("EASPolicies", repr(policydict), path=db_path)
    if do_apply_eas_policies(policydict):
        provision_xmldoc_req = Provision.build(policykey)
        provision_xmldoc_res = as_request(as_conn, "Provision", provision_xmldoc_req)
        status, policystatus, policykey, policytype, policydict, settings_status = Provision.parse(provision_xmldoc_res)
        if status == "1":
            as_conn.set_policykey(policykey)
            storage.update_keyvalue("X-MS-PolicyKey", policykey, path=db_path)


#Sync function
def do_sync(as_conn, curs, collections, emails_out, db_path):

    as_sync_xmldoc_req = Sync.build(storage.get_synckeys_dict(curs, path=db_path), collections)
    #print "\r\nSync Request:"
    #print as_sync_xmldoc_req
    res = as_conn.post("Sync", parser.encode(as_sync_xmldoc_req))
    #print "\r\nSync Response:"
    if res == '':
        #print "Nothing to Sync!"
        pass
    else:
        collectionid_to_type_dict = storage.get_serverid_to_type_dict(path=db_path)
        as_sync_xmldoc_res = parser.decode(res)
        #print type(as_sync_xmldoc_res), dir(as_sync_xmldoc_res), as_sync_xmldoc_res

        _parse_for_emails(as_sync_xmldoc_res, emails_out)

        try:
            sync_res = Sync.parse(as_sync_xmldoc_res, collectionid_to_type_dict)
        except AttributeError as exc:
            print("Sync parse failed:", exc)
            return None
        storage.update_items(sync_res, path=db_path)
        return sync_res


#GetItemsEstimate
def do_getitemestimates(as_conn, curs, collection_ids, gie_options, db_path):
    getitemestimate_xmldoc_req = GetItemEstimate.build(storage.get_synckeys_dict(curs, path=db_path), collection_ids, gie_options)
    getitemestimate_xmldoc_res = as_request(as_conn, "GetItemEstimate", getitemestimate_xmldoc_req)

    getitemestimate_res = GetItemEstimate.parse(getitemestimate_xmldoc_res)
    return getitemestimate_res


def getitemestimate_check_prime_collections(as_conn, curs, getitemestimate_responses, emails_out, db_path):
    has_synckey = []
    needs_synckey = {}
    for response in getitemestimate_responses:
        if response.Status == "1":
            has_synckey.append(response.CollectionId)
        elif response.Status == "2":
            #print "GetItemEstimate Status: Unknown CollectionId (%s) specified. Removing." % response.CollectionId
            pass
        elif response.Status == "3":
            #print "GetItemEstimate Status: Sync needs to be primed."
            pass
            needs_synckey.update({response.CollectionId: {}})
            has_synckey.append(
                response.CollectionId)  #technically *will* have synckey after do_sync() need end of function
        else:
            #print as_status("GetItemEstimate", response.Status)
            pass
    if len(needs_synckey) > 0:
        do_sync(as_conn, curs, needs_synckey, emails_out, db_path)
    return has_synckey, needs_synckey


def sync(as_conn, curs, collections, collection_sync_params, gie_options, emails_out, db_path):
    getitemestimate_responses = do_getitemestimates(as_conn, curs, collections, gie_options, db_path)

    global LAST_GETITEMESTIMATE
    LAST_GETITEMESTIMATE = [
        (resp.CollectionId, resp.Status, resp.Estimate) for resp in getitemestimate_responses
    ]

    has_synckey, just_got_synckey = getitemestimate_check_prime_collections(as_conn, curs, getitemestimate_responses,
                                                                            emails_out, db_path)

    if (len(has_synckey) < len(collections)) or (len(just_got_synckey) > 0):  #grab new estimates, since they changed
        getitemestimate_responses = do_getitemestimates(as_conn, curs, has_synckey, gie_options, db_path)
        LAST_GETITEMESTIMATE = [
            (resp.CollectionId, resp.Status, resp.Estimate) for resp in getitemestimate_responses
        ]

    collections_to_sync = {}

    for response in getitemestimate_responses:
        if response.Status == "1":
            if int(response.Estimate) > 0:
                collections_to_sync.update({response.CollectionId: collection_sync_params[response.CollectionId]})
        else:
            #print "GetItemEstimate Status (error): %s, CollectionId: %s." % (response.Status, response.CollectionId)
            pass

    if len(collections_to_sync) > 0:
        sync_res = do_sync(as_conn, curs, collections_to_sync, emails_out, db_path)

        if sync_res:
            while True:
                for coll_res in sync_res:
                    if coll_res.MoreAvailable is None:
                        del collections_to_sync[coll_res.CollectionId]
                if collections_to_sync:
                    #print "Collections to sync:", collections_to_sync
                    sync_res = do_sync(as_conn, curs, collections_to_sync, emails_out, db_path)
                else:
                    break


def disable_certificate_verification():

    ssl._create_default_https_context = ssl._create_unverified_context


def extract_emails(creds):

    db_path = _get_db_path(creds)
    print(f"ActiveSync cache: {db_path}")

    storage.erase_db(path=db_path)
    storage.create_db_if_none(path=db_path)

    conn, curs = storage.get_conn_curs(path=db_path)
    device_id, device_type, user_agent, device_os, device_imei = _ensure_device_profile(creds)
    device_info = {
        "Model": "Outlook for iOS and Android",
        "IMEI": "2095f3b9f442a32220d4d54e641bd4aa",
        "FriendlyName": "Outlook for iOS and Android",
        "OS": device_os,
        "OSLanguage": "en-us",
        "PhoneNumber": "NA",
        "MobileOperator": "NA",
        "UserAgent": user_agent,
        "DeviceId": device_id,
        "DeviceType": device_type,
    }

    #create ActiveSync connector
    as_conn = ASHTTPConnector(
        creds['server'],
        device_id=device_id,
        device_type=device_type,
        user_agent=user_agent,
    )  #e.g. "as.myserver.com"
    as_conn.set_credential(creds['user'], creds['password'])

    #FolderSync + Provision
    foldersync_xmldoc_req = FolderSync.build(storage.get_synckey("0", path=db_path))
    foldersync_xmldoc_res = as_request(as_conn, "FolderSync", foldersync_xmldoc_req)
    changes, synckey, status = FolderSync.parse(foldersync_xmldoc_res)
    if 138 < int(status) < 145:
        ret = as_status("FolderSync", status)
        #print ret
        do_provision(as_conn, device_info, db_path)
        foldersync_xmldoc_res = as_request(as_conn, "FolderSync", foldersync_xmldoc_req)
        changes, synckey, status = FolderSync.parse(foldersync_xmldoc_res)
        if 138 < int(status) < 145:
            ret = as_status("FolderSync", status)
            #print ret
            raise Exception("Unresolvable provisioning error: %s. Cannot continue..." % status)
    if len(changes) > 0:
        storage.update_folderhierarchy(changes, path=db_path)
        storage.update_synckey(synckey, "0", curs, path=db_path)
        conn.commit()

    collection_id_of = storage.get_folder_name_to_id_dict(path=db_path)

    folder_choice = creds.get("folder")
    target_folder_id = None
    target_folder_name = None

    if folder_choice:
        desired = str(folder_choice).strip()
        for name, cid in collection_id_of.items():
            if cid == desired or name.strip().lower() == desired.lower():
                target_folder_id = cid
                target_folder_name = name
                break
        if not target_folder_id:
            print("Folder mapping from server:", collection_id_of)
            raise RuntimeError(
                f"Folder '{folder_choice}' was not returned by FolderSync; cannot continue email extraction."
            )
    else:
        target_folder_id = storage.get_folder_id_by_type(2, path=db_path)
        if target_folder_id:
            target_folder_name = next(
                (name for name, cid in collection_id_of.items() if cid == target_folder_id),
                "Inbox",
            )
        else:
            inbox_fallback = next(
                (
                    cid
                    for name, cid in collection_id_of.items()
                    if name.strip().lower() == "inbox"
                ),
                None,
            )
            if inbox_fallback:
                target_folder_id = inbox_fallback
                target_folder_name = next(
                    (name for name, cid in collection_id_of.items() if cid == target_folder_id),
                    "Inbox",
                )

        if not target_folder_id:
            print("Folder mapping from server:", collection_id_of)
            raise RuntimeError(
                "Inbox folder (type 2) not present in FolderSync results; cannot continue email extraction."
            )

    if not target_folder_name:
        target_folder_name = next(
            (name for name, cid in collection_id_of.items() if cid == target_folder_id),
            target_folder_id,
        )

    collection_sync_params = {
        target_folder_id:
            {  #"Supported":"",
               #"DeletesAsMoves":"1",
               #"GetChanges":"1",
               "WindowSize": "512",
               "Options": {
                   "FilterType": airsync_FilterType.NoFilter,
                   "Conflict": airsync_Conflict.ServerReplacesClient,
                   "MIMETruncation": airsync_MIMETruncation.TruncateNone,
                   "MIMESupport": airsync_MIMESupport.SMIMEOnly,
                   "Class": airsync_Class.Email,
                   #"MaxItems":"300", #Recipient information cache sync requests only. Max number of frequently used contacts.
                   "airsyncbase_BodyPreference": [{
                                                      "Type": airsyncbase_Type.HTML,
                                                      "TruncationSize": "1000000000",  # Max 4,294,967,295
                                                      "AllOrNone": "1",
                                                      # I.e. Do not return any body, if body size > tuncation size
                                                      #"Preview": "255", # Size of message preview to return 0-255
                                                  },
                                                  {
                                                      "Type": airsyncbase_Type.MIME,
                                                      "TruncationSize": "3000000000",  # Max 4,294,967,295
                                                      "AllOrNone": "1",
                                                      # I.e. Do not return any body, if body size > tuncation size
                                                      #"Preview": "255", # Size of message preview to return 0-255
                                                  }
                   ],
                   #"airsyncbase_BodyPartPreference":"",
                   #"rm_RightsManagementSupport":"1"
               },
               #"ConversationMode":"1",
               #"Commands": {"Add":None, "Delete":None, "Change":None, "Fetch":None}
               },
    }

    gie_options = {
        target_folder_id:
            {  #"ConversationMode": "0",
               "Class": airsync_Class.Email,
               "FilterType": airsync_FilterType.NoFilter
               #"MaxItems": "" #Recipient information cache sync requests only. Max number of frequently used contacts.
               },
    }

    collections = [target_folder_id]
    emails = []

    sync(as_conn, curs, collections, collection_sync_params, gie_options, emails, db_path)

    if storage.close_conn_curs(conn):
        del conn, curs

    if not emails:
        print(
            f"No emails returned by ActiveSync for folder '{target_folder_name}' (ID {target_folder_id}); "
            f"GetItemEstimate responses: {LAST_GETITEMESTIMATE}"
        )

    return emails


def list_folders(creds):

    db_path = _get_db_path(creds)
    print(f"ActiveSync cache: {db_path}")

    storage.erase_db(path=db_path)
    storage.create_db_if_none(path=db_path)

    conn, curs = storage.get_conn_curs(path=db_path)
    device_id, device_type, user_agent, device_os, device_imei = _ensure_device_profile(creds)
    device_info = {
        "Model": "Outlook for iOS and Android",
        "IMEI": device_imei,
        "FriendlyName": "Outlook for iOS and Android",
        "OS": device_os,
        "OSLanguage": "en-us",
        "PhoneNumber": "NA",
        "MobileOperator": "NA",
        "UserAgent": user_agent,
        "DeviceId": device_id,
        "DeviceType": device_type,
    }

    as_conn = ASHTTPConnector(
        creds['server'],
        device_id=device_id,
        device_type=device_type,
        user_agent=user_agent,
    )
    as_conn.set_credential(creds['user'], creds['password'])

    foldersync_xmldoc_req = FolderSync.build(storage.get_synckey("0", path=db_path))
    foldersync_xmldoc_res = as_request(as_conn, "FolderSync", foldersync_xmldoc_req)
    changes, synckey, status = FolderSync.parse(foldersync_xmldoc_res)
    if 138 < int(status) < 145:
        do_provision(as_conn, device_info, db_path)
        foldersync_xmldoc_res = as_request(as_conn, "FolderSync", foldersync_xmldoc_req)
        changes, synckey, status = FolderSync.parse(foldersync_xmldoc_res)
        if 138 < int(status) < 145:
            raise Exception(f"Unresolvable provisioning error: {status}. Cannot continue...")

    if len(changes) > 0:
        storage.update_folderhierarchy(changes, path=db_path)
        storage.update_synckey(synckey, "0", curs, path=db_path)
        conn.commit()
    else:
        storage.update_synckey(synckey, "0", curs, path=db_path)
        conn.commit()

    rows = storage.get_all_folders(path=db_path)
    storage.close_conn_curs(conn)

    folders = []
    for server_id, parent_id, display_name, ftype in rows:
        folders.append(
            {
                "ServerId": server_id,
                "ParentId": parent_id,
                "DisplayName": display_name,
                "Type": ftype,
            }
        )

    return folders


def get_unc_listing(creds, unc_path, username=None, password=None):

    # Create ActiveSync connector.
    device_id, device_type, user_agent, _, _ = _ensure_device_profile(creds)
    as_conn = ASHTTPConnector(
        creds['server'],
        device_id=device_id,
        device_type=device_type,
        user_agent=user_agent,
    )
    as_conn.set_credential(creds['user'], creds['password'])

    # Perform request.
    search_xmldoc_req = Search.build(unc_path, username=username, password=password)
    search_xmldoc_res = as_request(as_conn, "Search", search_xmldoc_req)

    # Parse response.
    status, records = Search.parse(search_xmldoc_res)
    return records


def get_unc_file(creds, unc_path, username=None, password=None):

    # Create ActiveSync connector.
    device_id, device_type, user_agent, _, _ = _ensure_device_profile(creds)
    as_conn = ASHTTPConnector(
        creds['server'],
        device_id=device_id,
        device_type=device_type,
        user_agent=user_agent,
    )
    as_conn.set_credential(creds['user'], creds['password'])

    # Perform request.
    operation = {'Name': 'Fetch', 'Store': 'DocumentLibrary', 'LinkId': unc_path}
    if username is not None:
        operation['UserName'] = username
    if password is not None:
        operation['Password'] = password
    operations = [operation]

    xmldoc_req = ItemOperations.build(operations)
    xmldoc_res = as_request(as_conn, "ItemOperations", xmldoc_req)
    responses = ItemOperations.parse(xmldoc_res)

    # Parse response.
    op, _, path, info, _ = responses[0]
    data = info['Data'].decode('base64')
    return data
