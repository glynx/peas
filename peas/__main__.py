import base64
import binascii
import errno
import hashlib
import os
import random
import string
import sys

from argparse import ArgumentParser, BooleanOptionalAction, Namespace
from pathlib import Path, PureWindowsPath
from random import choice
from string import ascii_uppercase, digits

import peas


R = '\033[1;31m'  # red
G = '\033[0;32m'  # green
Y = '\033[0;33m'  # yellow
M = '\033[0;35m'  # magenta
S = '\033[0m'     # reset


def info(msg: str) -> None:
    sys.stdout.write('{0}[*] {1}{2}\n'.format(G, msg, S))


def warning(msg: str) -> None:
    sys.stdout.write('{0}[!] {1}{2}\n'.format(Y, msg, S))


def error(msg: str) -> None:
    sys.stderr.write('{0}[-] {1}{2}\n'.format(R, msg, S))


def positive(msg: str) -> None:
    sys.stdout.write('{0}[+] {1}{2}\n'.format(G, msg, S))


def create_arg_parser() -> ArgumentParser:
    parser = ArgumentParser()
    parser.add_argument('-s', '--server', required=True, metavar='IP|FQDN')
    parser.add_argument('-u', '--user', required=True, metavar='[DOMAIN\\]USER')
    parser.add_argument('-p', '--password', required=True, metavar='PASSWORD')
    parser.add_argument('-q', '--quiet', action=BooleanOptionalAction, help='Suppress all unnecessary output')
    parser.add_argument('--verify-ssl', action=BooleanOptionalAction, help='Verify SSL certificates')
    parser.add_argument('--smb-user', metavar='USER', help='Username for SMB operations')
    parser.add_argument('--smb-password', metavar='PASSWORD', help='Password for SMB operations')

    group = parser.add_argument_group('device')
    # passed to ActiveSync() via 'creds'
    group.add_argument('--user-agent', default='Apple-iPad15C3/2207.100', help='Set DeviceUserAgent')
    group.add_argument('--device-id', default=None, help='Set DeviceId')
    group.add_argument('--device-type', default='iPad', help='Set DeviceType')
    # passed to Provision.build() via 'device_info'
    group.add_argument('--device-name', default='iPad Air 11-inch (M3)', help='Set FriendlyName')
    group.add_argument('--device-imei', default='', help='Set DeviceImei')
    group.add_argument('--device-mobile-operator', default='', help='Set DeviceMobileOperator')
    group.add_argument('--device-os', default='iOS 18.6.2 22G100', help='Set DeviceOS')
    group.add_argument('--device-language', default='de-DE', help='Set DeviceOSLanguage')
    group.add_argument('--device-phone-number', default='', help='Set DeviceTelephoneNumber')
    group.add_argument('--device-model', default='iPad15C3', help='Set DeviceModel')
    # ClientVersion is hardcoded in ASHTTPConnector() from pyActiveSync/objects/MSASHTTP.py

    group = parser.add_argument_group('general')
    group.add_argument('--check', action='store_true', help='Check if account can be accessed with given password')
    group.add_argument('--provision-device', action='store_true', help='Register fake device')

    group = parser.add_argument_group('email')
    group.add_argument('--list-folders', action='store_true', help='List email folders')
    group.add_argument('--folder', metavar='NAME|ID', help='Folder to retrieve emails from')
    group.add_argument('--emails', dest='extract_emails', action='store_true', help='Retrieve emails')

    group = parser.add_argument_group('smb')
    group.add_argument('--list-unc', metavar='UNC_PATH', help='List the files at a given UNC path')
    group.add_argument('--dl-unc', metavar='UNC_PATH', help='Download the file at a given UNC path')
    group.add_argument('--crawl-unc', metavar='UNC_PATH', help='Recursively list all files at a given UNC path')
    group.add_argument('--brute-unc', action='store_true', help='Recursively list all files at a given UNC path')
    group.add_argument('-o', '--output-file', dest='file', metavar='FILEPATH', help='Output file')
    group.add_argument('-O', '--output-dir', dest='output_dir', metavar='DIRPATH', help='Output directory for specific commands, not combined with -o')
    group.add_argument('-F', '--format', metavar='repr,hex,b64,stdout,stderr,file', help='Output formatting and encoding')
    group.add_argument('--download', action='store_true', default=False, help='Download files at a given UNC path while crawling (--crawl-unc)')
    group.add_argument('--prefix', help='NetBIOS hostname prefix (--brute-unc)')
    group.add_argument('--pattern', action='append', default=[], help='Filter files by name (--crawl-unc)')

    return parser


def init_authed_client(options: Namespace) -> peas.Peas:
    client = peas.Peas()
    client.set_creds(options.__dict__)
    if not options.verify_ssl:
        client.disable_certificate_verification()
    return client


def check(options: Namespace) -> None:
    client = init_authed_client(options)
    creds_valid = client.check_auth()
    if creds_valid:
        positive('Auth success.')
    else:
        error('Auth failure.')


def extract_emails(options):
    client = init_authed_client(options)
    if not client:
        return

    emails = client.extract_emails()
    # TODO: Output the emails in a more useful format.
    if options.output_dir:
        Path(options.output_dir).mkdir(parents=True, exist_ok=True)

    for i, email in enumerate(emails):

        payload = email.strip() if hasattr(email, 'strip') else email

        if options.output_dir:
            digest_input = payload if isinstance(payload, (bytes, bytearray)) else str(payload).encode('utf-8')
            fname = 'email_%d_%s.xml' % (i, hashlib.md5(digest_input).hexdigest())
            path = os.path.join(options.output_dir, fname)
            if isinstance(payload, (bytes, bytearray)):
                to_write = payload + b'\n'
            else:
                to_write = (payload + '\n').encode('utf-8')
            with open(path, 'wb') as fh:
                fh.write(to_write)
        else:
            if isinstance(payload, (bytes, bytearray)):
                output_result(payload + b'\n', options, default='stdout')
            else:
                output_result(payload + '\n', options, default='stdout')

    if options.output_dir:
        info("Wrote %d emails to %r" % (len(emails), options.output_dir))


def provision_device(options: Namespace) -> None:
    client = init_authed_client(options)
    client.provision_device()


def list_folders(options: Namespace) -> None:
    client = init_authed_client(options)
    folders = client.list_folders()
    if not folders:
        info('No folders returned by server.')
        return
    lines = []
    for folder in folders:
        name = folder.get('DisplayName', '-')
        server_id = folder.get('ServerId', '-')
        parent_id = folder.get('ParentId', '-')
        ftype = folder.get('Type', '-')
        lines.append(f'{name} (ID: {server_id}, Type: {ftype}, Parent: {parent_id})')
    output_result('\n'.join(lines), options, default='stdout')


def list_unc_helper(client: peas.Peas, uncpath: str, options: Namespace, show_parent=True) -> None:
    records = client.get_unc_listing(uncpath)
    output = []
    if not options.quiet and show_parent:
        info("Listing: %s\n" % (uncpath,))
    for record in records:
        name = record.get('DisplayName')
        uncpath = record.get('LinkId')
        is_folder = record.get('IsFolder') == '1'
        is_hidden = record.get('IsHidden') == '1'
        size = record.get('ContentLength', '0') + 'B'
        ctype = record.get('ContentType', '-')
        last_mod = record.get('LastModifiedDate', '-')
        created = record.get('CreationDate', '-')
        attrs = ('f' if is_folder else '-') + ('h' if is_hidden else '-')
        output.append("%s %-24s %-24s %-24s %-12s %s" % (attrs, created, last_mod, ctype, size, uncpath))
    output_result('\n'.join(output), options, default='stdout')


def list_unc(options: Namespace) -> None:
    client = init_authed_client(options)
    list_unc_helper(client, options.list_unc, options)


def dl_unc(options):
    client = init_authed_client(options)
    if not client:
        return

    path = options.dl_unc
    data = client.get_unc_file(path)

    if not options.quiet:
        info("Downloading: %s\n" % (path,))

    output_result(data, options, default='repr')


def crawl_unc_helper(client, uncpath, patterns, options):
    records = client.get_unc_listing(uncpath)
    for record in records:
        if record['IsFolder'] == '1':
            if record['LinkId'] == uncpath:
                continue
            crawl_unc_helper(client, record['LinkId'], patterns, options)
        else:
            for pattern in patterns:
                if pattern.lower() in record['LinkId'].lower():
                    if options.download:
                        try:
                            data = client.get_unc_file(record['LinkId'])
                        except TypeError:
                            pass
                        else:
                            winpath = PureWindowsPath(record['LinkId'])
                            posixpath = Path(winpath.as_posix()) # Windows path to POSIX path
                            posixpath = Path(*posixpath.parts[1:]) # get rid of leading "/"
                            dirpath = posixpath.parent
                            newdirpath = mkdir_p(dirpath)
                            filename = str(newdirpath / posixpath.name)
                            try:
                                with open(filename, 'w') as fd:
                                    fd.write(data)
                            # If path name becomes too long when filename is added
                            except IOError as e:
                                if e.errno == errno.ENAMETOOLONG:
                                    rootpath = Path(newdirpath.parts[0])
                                    extname = posixpath.suffix
                                    # Generate random name for the file and put it in the root share directory
                                    filename = ''.join(choice(ascii_uppercase + digits) for _ in range(8)) + extname
                                    filename = str(rootpath / filename)
                                    with open(filename, 'w') as fd:
                                        fd.write(data)
                                    warning('File %s"%s"%s was renamed and written to %s"%s"%s' % (M, str(posixpath), S, M, filename, S))
                                else:
                                    raise
                            else:
                                if dirpath != newdirpath:
                                    warning('File %s"%s"%s was written to %s"%s"%s' % (M, str(posixpath), S, M, filename, S))

                    list_unc_helper(client, record['LinkId'], options, show_parent=False)

                    break


def crawl_unc(options):
    client = init_authed_client(options)
    if options.download:
        info('Listing and downloading all files: %s' % (options.crawl_unc,))
    else:
        info('Listing all files: %s' % (options.crawl_unc,))
    crawl_unc_helper(client, options.crawl_unc, options.patterns or [''], options)


def generate_wordlist(prefix=None):
    with open('hostnames.txt', 'r') as fd:
        hostnames = [line.strip() for line in fd]

    wordlist = []
    if prefix is not None:
        for h in hostnames:
            for i in range(1, 5):
                wordlist.append('{prefix}{i:02}-{h}'.format(prefix=prefix, i=i, h=h))  # PREFIX01-DC
                wordlist.append('{prefix}{i}-{h}'.format(prefix=prefix, i=i, h=h))     # PREFIX1-DC
                for j in range(1, 10):
                    wordlist.append('{prefix}{i:02}-{h}-{j:02}'.format(prefix=prefix, i=i, h=h, j=j))  # PREFIX01-DC-01
                    wordlist.append('{prefix}{i}-{h}-{j:02}'.format(prefix=prefix, i=i, h=h, j=j))     # PREFIX1-DC-01
                    wordlist.append('{prefix}{i:02}-{h}-{j}'.format(prefix=prefix, i=i, h=h, j=j))     # PREFIX01-DC-1
                    wordlist.append('{prefix}{i}-{h}-{j}'.format(prefix=prefix, i=i, h=h, j=j))        # PREFIX1-DC-1
                    wordlist.append('{prefix}{i:02}-{h}{j:02}'.format(prefix=prefix, i=i, h=h, j=j))   # PREFIX01-DC01
                    wordlist.append('{prefix}{i}-{h}{j:02}'.format(prefix=prefix, i=i, h=h, j=j))      # PREFIX1-DC01
                    wordlist.append('{prefix}{i:02}-{h}{j}'.format(prefix=prefix, i=i, h=h, j=j))      # PREFIX01-DC1
                    wordlist.append('{prefix}{i}-{h}{j}'.format(prefix=prefix, i=i, h=h, j=j))         # PREFIX1-DC1

    for h in hostnames:
        wordlist.append(h)  # DC
        for i in range(1, 10):
            wordlist.append('{h}-{i:02}'.format(h=h, i=i))  # DC-01
            wordlist.append('{h}-{i}'.format(h=h, i=i))     # DC-1
            wordlist.append('{h}{i:02}'.format(h=h, i=i))   # DC01
            wordlist.append('{h}{i}'.format(h=h, i=i))      # DC1

    return wordlist


def brute_unc(options):
    client = init_authed_client(options)
    if not client:
        return

    prefix = None
    if options.prefix:
        prefix = options.prefix.upper()

    wordlist = generate_wordlist(prefix)
    for w in wordlist:
        list_unc_helper(client, r'\\%s' % w, options, show_parent=False)


def output_result(data, options, default='repr'):
    fmt = options.format
    if not fmt:
        fmt = 'file' if options.file else default
    actions = fmt.split(',')

    # Write to file at the end if a filename is specified.
    if options.file and 'file' not in actions:
        actions.append('file')

    # Process the output based on the format/encoding options chosen.
    encoding_used = True
    payload = data
    for action in actions:
        if action == 'repr':
            payload = repr(payload)
            encoding_used = False
        elif action == 'hex':
            raw = payload if isinstance(payload, (bytes, bytearray)) else str(payload).encode('utf-8')
            payload = binascii.hexlify(raw).decode('ascii')
            encoding_used = False
        elif action in ['base64', 'b64']:
            raw = payload if isinstance(payload, (bytes, bytearray)) else str(payload).encode('utf-8')
            payload = base64.b64encode(raw).decode('ascii')
            encoding_used = False
        elif action == 'stdout':
            if isinstance(payload, (bytes, bytearray)):
                sys.stdout.buffer.write(payload)
                sys.stdout.buffer.write(b'\n')
            else:
                print(payload)
            encoding_used = True
        elif action == 'stderr':
            if isinstance(payload, (bytes, bytearray)):
                sys.stderr.buffer.write(payload)
            else:
                sys.stderr.write(payload)
            encoding_used = True
        # Allow the user to write the file after other encodings have been applied.
        elif action == 'file':
            if options.file:
                to_write = payload if isinstance(payload, (bytes, bytearray)) else str(payload).encode('utf-8')
                with open(options.file, 'wb') as fh:
                    fh.write(to_write)
                if not options.quiet:
                    info("Wrote %d bytes to %r." % (len(to_write), options.file))
            else:
                error("No filename specified.")
            encoding_used = True

    # Print now if an encoding has been used but never output.
    if not encoding_used:
        if isinstance(payload, (bytes, bytearray)):
            sys.stdout.buffer.write(payload)
            sys.stdout.buffer.write(b'\n')
        else:
            print(payload)


def mkdir_p(dirpath):
    try:
        dirname = str(dirpath)
        os.makedirs(dirname)
    except OSError as e:
        if e.errno == errno.EEXIST and os.path.isdir(dirname):
            pass
        # If directory path name already too long
        elif e.errno == errno.ENAMETOOLONG:
            dirpath = Path(dirpath.parts[0])
        else:
            raise

    return dirpath


def main() -> None:
    parser = create_arg_parser()
    opts = parser.parse_args()
    if not opts.smb_user and not opts.smb_password:
        opts.smb_user = opts.user
        opts.smb_password = opts.password
    if not opts.device_id:
        opts.device_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(26))
        print(f'Warning: Using random device id {opts.device_id}. By default a user can register at most 20 devices.')
    if opts.output_dir:
        Path(opts.output_dir).mkdir(exist_ok=True)
    if opts.check:
        check(opts)
    if opts.list_folders:
        list_folders(opts)
    if opts.extract_emails:
        extract_emails(opts)
    if opts.list_unc:
        list_unc(opts)
    if opts.dl_unc:
        dl_unc(opts)
    if opts.crawl_unc:
        crawl_unc(opts)
    if opts.brute_unc:
        brute_unc(opts)
    if opts.provision_device:
        provision_device(opts)


if __name__ == '__main__':
    main()
