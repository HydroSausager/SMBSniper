import sqlite3
import argparse
import sys
import math
import time
import shutil
import getpass
import os
import socket
from impacket.nmb import NetBIOSTimeout
import threading
import getpass
from os.path import exists
from impacket.smbconnection import SMBConnection, smb, SessionError
from impacket.examples.utils import parse_target
import impacket
import logging
import dns.resolver
from colorama import Fore, Style
import datetime
from netaddr import IPRange, AddrFormatError, IPAddress, IPNetwork

try:
    import xlsxwriter
except:
    print(Fore.LIGHTYELLOW_EX + "You need to install XlsxWriter to generate xlsx files")

import re

logger = logging.getLogger('logger')
logging.basicConfig(level='CRITICAL')

import re
import tqdm

db = sqlite3.connect('database.db')
sql = db.cursor()
threads_targets = []

closed_445 = []
not_resolved = []
no_null_session = []

interesting_filenames = [
    '\.wim',
    '\.ovpn',
    '\.pfx',
    '\.bat',
    '\.ps1',
    '\.conf',
    '\.vmdk',
    '\.config',
    '\.xlsm',
    '\.docm',
    '\.vnc',
    '\.vbs',
    '\.php',
    '\.asp',
    '\.aspx',

    'id.rsa',
    'unattend.*\.xml',
    'ntuser\.dat',
    'consolehost_history\.txt',
    'commonsetting\.ini',
    'bootstrap.*\.ini',

    'password', 'парол',
    'sensitive',
    'admin',
    'login',
    'secret',
    'creds',
    'credential',
    '/Protect/S-1-5'

]


def db_init(db, sql, close=False):
    sql.execute("""CREATE TABLE IF NOT EXISTS hosts(
        host_id INTEGER PRIMARY KEY,
        ip VARCHAR(16) NOT NULL,
        hostname VARCHAR(50),
        domain VARCHAR(50),
        os VARCHAR(50),
        os_build VARCHAR(50),
        port_445_is_open TINYINT,
        port_139_is_open TINYINT,
        UNIQUE(ip)
        )""")
    # db.commit()

    sql.execute("""CREATE TABLE IF NOT EXISTS shares(
    share_id INTEGER PRIMARY KEY,
    host_id INTEGER,
    share_name VARCHAR(100) NOT NULL,
    share_remark VARCHAR(50),
    empty_cred_access TINYINT,
    guest_cred_access TINYINT,
    UNIQUE(host_id, share_name, share_remark)
    )""")

    sql.execute("""CREATE TABLE IF NOT EXISTS share_content(
    file_id INTEGER PRIMARY KEY,
    share_id BIGINT,
    parent_folder TEXT,
    filename TEXT,
    is_file TINYINT,
    extension VARCHAR(20),
    file_size BIGINT,
    creation_date TEXT,
    modification_date TEXT,
    ctime BIGINT,
    mtime BIGINT,
    UNIQUE(share_id,parent_folder,filename,is_file)
    )""")

    sql.execute("""CREATE TABLE IF NOT EXISTS users(
    user_id INTEGER PRIMARY KEY,
    username VARCHAR(50),
    domain VARCHAR(20)
    )""")
    try:
        sql.execute("""INSERT INTO users(user_id, username, domain) VALUES(
        0,
        'Guest',
        NULL
        )""")
    except:
        pass

    sql.execute("""CREATE TABLE IF NOT EXISTS permissions(
        id INTEGER PRIMARY KEY,
        userid BIGINT,
        share_id BIGINT,
        access_type TINYINT
        )""")

    # full info creation
    sql.execute(
        'CREATE VIEW IF NOT EXISTS "full" AS select hostname as hostname, share_name as share_name, share_remark as share_remark, parent_folder || filename as full_path, filename, is_file as is_file, extension, file_size, creation_date, modification_date  from share_content JOIN shares ON shares.share_id == share_content.share_id JOIN hosts ON hosts.host_id == shares.host_id')

    db.commit()
    if close:
        sql.close()
        db.close()
    # print(Fore.LIGHTYELLOW_EX + 'DB initialized')



def get_targets(targets):
    """
    Get targets from file or string
    :param targets: List of targets
    :return: List of IP addresses
    """
    ret_targets = []
    for target in targets:
        if os.path.exists(target):
            with open(target, 'r') as target_file:
                for target_entry in target_file:
                    ret_targets += parse_targets(target_entry)
        else:
            ret_targets += parse_targets(target)
    return [str(ip) for ip in ret_targets]
def get_args():
    global args
    parser = argparse.ArgumentParser(description='Handy SMB script',
                                     usage=f'python3 {sys.argv[0]} target (or targetfile.txt) -u user@domain [-p password] [-t threads count]')

    #parser.add_argument('target', action="store", type=str, help='target\'s ip/fqdn or file with targets')
    parser.add_argument('target', action='store',
                        help='[[domain/]username[:password]@]<target address or IP range or IP list file>')

    parser.add_argument('-t', '--threads', action="store",
                        dest="threads", help='Threads count', default=1, type=int)

    parser.add_argument('-d', '--depth', action="store", type=int,
                        dest="depth", default=3, help='Depth of crawling')
    parser.add_argument('-e', '--exclude', action="store", default='',
                        dest="excluded-shares", help='Shares excluded from share crawling separated by comma')
    parser.add_argument('-x', '--xlsx', action="store",
                        dest="xlsx-filename", help='Full results xlsx filename')
    parser.add_argument('-H', '--hash', action="store",
                        dest="ntlm-hash", help='NTLM Hash', default='')
    parser.add_argument('--timeout', action="store", type=float,
                        dest="timeout", help='timeout for connections', default=0.5)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()

    args = vars(parser.parse_args())

    args['domain'], args['username'], args['password'], args['address'] = parse_target(args['target'])

    # try:
    #     username = args['username'].split('@')[0]
    #     user_domain = args['username'].split('@')[1]
    # except:
    #     print(Fore.LIGHTRED_EX + "Wrong username, use user@domain.com format")
    #     sys.exit(1)

    if args['password'] is None and args['ntlm-hash'] is None:
        print(Fore.LIGHTRED_EX + "Are you dumb? Use password OR hash...")
        sys.exit(1)

    if not args['password'] and not args['ntlm-hash']:
        if not args['username']:
            print(Fore.LIGHTYELLOW_EX + "No username and password/hash specified, will try null session")

        else:
            args['password'] = getpass.getpass(prompt='Password: ', stream=None)


    args['excluded-shares'] = args['excluded-shares'].split(',')

    if not args['target']:
        parser.print_help()
        sys.exit(1)


def db_update_host_ports(db, sql, ip, port_445_is_open=None, port_139_is_open=None):
    """
    Just updates host's states of smb ports in "hosts" table
    :param db:                  sqlite db object
    :param sql:                 sql cursor
    :param ip:                  target ip
    :param port_445_is_open:    puppy tail
    :param port_139_is_open:    distance to the moon
    :return:                    nothing
    """
    query = (f'''UPDATE  hosts
            SET port_445_is_open = ?,
            port_139_is_open = ?
            WHERE ip = ?
            ''', (port_445_is_open, port_139_is_open, ip))
    sql.execute(*query)
    db.commit()


def db_insert_host(db, sql, ip=None, hostname=None, host_domain=None, host_os=None, host_os_build=None):
    """
    Inserts or updates host in "hosts" table
    :param db:              sqlite db object
    :param sql:             sql cursor
    :param ip:              target's ip
    :param hostname:        target's hostname
    :param host_domain:     target host's domain
    :param host_os:         target host's os
    :param host_os_build:   target host's os build number
    :return:                nothing
    """

    # first we are checking is host already in "hosts" table
    result = sql.execute(f'SELECT * FROM hosts WHERE ip = ?', (ip,)).fetchone()

    # some linux hosts return \x00 in host_domain, we need to delete it
    host_domain = host_domain.replace('\x00', '') if type(host_domain) == str else host_domain

    # in case of local auth domain = hostname, it looks ugly in db
    if host_domain != hostname and host_domain and host_domain not in hostname:
        hostname += "." + host_domain

    # we're updating host if host already in db and any of it's fields is None (no domain/hostname/whatever)
    if result and any([result[i] == None for i in range(2, len(result))]):
        # range(2, x) because 0 - host_id, 1 - host_ip which is always not None
        query = ('''UPDATE  hosts
        SET hostname = ?,
        domain = ?,
        os = ?,
        os_build = ?
        WHERE ip = ?''',
                 (hostname, host_domain, host_os, host_os_build, ip))
    elif not result:
        # inserting host if it is not in db
        query = ('''INSERT INTO hosts(ip, hostname, domain, os, os_build) VALUES (
        ?, ?, ?, ?, ?)''', (ip, hostname, host_domain, host_os, host_os_build))
    else:
        # if host already in db, just exiting
        return
    try:
        sql.execute(*query)
    except Exception as e:  # sqlite3.IntegrityError:
        tqdm.tqdm.write(Fore.LIGHTRED_EX + "Exception while db_insert_host")
        tqdm.tqdm.write(Fore.LIGHTRED_EX + e)
        pass
    db.commit()


def db_get_host_id_by_ip(sql, ip):
    """
    returns host_id by its ip from "hosts" table
    :param sql:
    :param ip:
    :return:
    """
    host_id = sql.execute('SELECT host_id FROM hosts WHERE ip = ?', (ip,)).fetchone()[0]

    return host_id


def db_get_share_id(sql, ip, share_name):
    host_id = db_get_host_id_by_ip(sql, ip)
    share_id = \
        sql.execute(
            f'SELECT share_id FROM shares WHERE host_id = {host_id} AND share_name = "{share_name}"').fetchone()[0]
    share_id = int(share_id)
    return share_id


def db_insert_share(db, sql, ip=None, share_name=None, share_remark=None):
    host_id = db_get_host_id_by_ip(sql, ip)

    query = ('INSERT INTO shares(host_id, share_name,share_remark) VALUES (?,?,?)', (host_id, share_name, share_remark))

    try:
        sql.execute(*query)
    except sqlite3.IntegrityError:
        pass
    db.commit()


def db_insert_share_content(db, sql, ip=None, share_name=None, parent_folder=None, filename=None, is_file=True,
                            extension=None, file_size=0, creation_date=None, ctime=0, modification_date=None,
                            mtime=0):
    share_id = db_get_share_id(sql, ip, share_name)
    if type(extension) == str:
        extension = extension.lower()

    query = (f'''INSERT INTO share_content(share_id, parent_folder, filename, 
    is_file, extension, file_size, creation_date, ctime, modification_date, mtime) 
    VALUES (?,?,?,?,?,?,?,?,?,?)''',
             (share_id,
              parent_folder,
              filename,
              is_file,
              extension,
              int(file_size),
              creation_date,
              int(ctime),
              modification_date,
              int(mtime)))

    try:
        sql.execute(*query)
    except Exception as e:
        tqdm.tqdm.write(Fore.LIGHTRED_EX + 'Exception while inserting share_content')
        tqdm.tqdm.write(Fore.LIGHTRED_EX + e)
        pass
    db.commit()
    return


def check_port(host, port, timeout=0.2):
    a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    a_socket.settimeout(timeout)
    location = (host, port)
    result_of_check = a_socket.connect_ex(location)

    if result_of_check == 0:
        return 1
    else:
        return 0


def make_connection(thread_db, thread_sql, user_domain=None, address=None, target_ip=None, port=445, do_not_login=False,
                    timeout=5, thread_index=0):
    """
    :param thread_db:       sqlite db object
    :param thread_sql:      sql cursor
    :param user_domain:     user domain
    :param address:         ip/fqdn
    :param target_ip:       ip
    :param port:            only 445 for now
    :param do_not_login:    do not check anon login for host info gathering
    :param timeout:         SMB connection timeout
    :param thread_index:    current thread index
    :return:                not logged in connection
    """

    # first checking ports and updating db info
    port_445_is_open = check_port(target_ip, 445, timeout=args['timeout'])
    # port_139_is_open = check_port(target_ip, 139)
    db_update_host_ports(thread_db, thread_sql, target_ip, port_445_is_open=port_445_is_open,
                         port_139_is_open=False)

    try:
        if not port_445_is_open:
            #tqdm.tqdm.write(Fore.LIGHTYELLOW_EX + f"Thr {thread_index} - Port 445 is closed on " + (f'{address} ({target_ip})' if address != target_ip else address))
            closed_445.append(address)
            return

        connection = SMBConnection(address, target_ip, sess_port=port, timeout=timeout)
        try:
            # trying to get host info using anon connection
            if do_not_login:
                return connection

            connection.login('', '')
            host_info = db_update_host_info_using_connection(thread_db, thread_sql, connection=connection)

            # if host_info['host_domain'].lower() != user_domain.lower():
            #     tqdm.tqdm.write(Fore.LIGHTYELLOW_EX +
            #                     f"Thr {thread_index} - Host's {host_info['hostname']} ({host_info['ip']}) domain ({host_info['host_domain']}) not in users domain ({user_domain}), skipping...")
            #     return

            # returned connection must be logged off for next logins
            connection.logoff()
        except Exception as e:
            logger.warning(f'No null session on {target_ip}')
            no_null_session.append(target_ip)
            try:
                connection = SMBConnection(address, target_ip, sess_port=port, timeout=timeout)
                return connection
            except:
                return
        return connection
    except Exception as e:
        logger.error(f'Failed to connect to {target_ip}')
        return


def db_update_host_info_using_connection(db, sql, connection):
    """
    Used for basic host enumeration
    :param target_ip: target ip
    :param connection: Logged in connection
    :return: dict of crawled data
    """
    try:
        target_ip = connection.getRemoteHost()
        hostname = connection.getServerName().lower()
        host_domain = connection.getServerDNSDomainName().lower()
        host_OS = connection.getServerOS()
        try:
            host_OS_build = connection.getServerOSBuild()
        except:
            host_OS_build = None

        if host_domain != hostname:
            hostname += "." + host_domain

        crawled_host_data = {
            'ip': target_ip,
            'hostname': hostname,
            'host_domain': host_domain,
            'host_os': host_OS,
            'host_os_build': host_OS_build
        }

    except Exception as e:
        tqdm.tqdm.write(Fore.LIGHTRED_EX + f"Failed to get host_info of {connection.getRemoteHost()}")
        crawled_host_data = {
            'ip': target_ip,  # if target_ip else None,
            'hostname': hostname,  # if hostname else None,
            'host_domain': host_domain,  # if host_domain else None,
            'host_os': host_OS,  # if host_OS else None,
            'host_os_build': host_OS_build  # if host_OS_build else None
        }
    db_insert_host(db, sql, **crawled_host_data)

    return crawled_host_data


def get_shares(db, sql, connection):
    found_shares = []

    for share in connection.listShares():
        share_name = share['shi1_netname'][:-1]
        share_remark = share['shi1_remark'][:-1]
        found_shares.append(share_name)
        db_insert_share(db, sql, ip=connection.getRemoteHost(), share_name=share_name, share_remark=share_remark)

    return found_shares


def get_ip_from_db_by_hostname(sql, hostname=None):
    """
    This function tries to get host ip from db by its FQDN
    :param hostname:
    :return:
    """
    query = f"select ip from hosts where hostname = '{hostname}'"
    try:
        result = sql.execute(query).fetchone()
    except Exception as e:
        pass
    if result == None:
        return None
    return str(result[0])


def get_hostname_from_db_by_ip(ip=None):
    query = f"select hostname from hosts where ip = '{ip}'"
    result = sql.execute(query).fetchone()
    return result


def parse_target_arg(target=None):
    if not exists(target):
        if '-' in target:
            ip_range = target.split('-')
            try:
                t = IPRange(ip_range[0], ip_range[1])
            except AddrFormatError:
                try:
                    start_ip = IPAddress(ip_range[0])

                    start_ip_words = list(start_ip.words)
                    start_ip_words[-1] = ip_range[1]
                    start_ip_words = [str(v) for v in start_ip_words]

                    end_ip = IPAddress('.'.join(start_ip_words))

                    t = IPRange(start_ip, end_ip)
                except AddrFormatError:
                    t = target
        else:
            try:
                t = IPNetwork(target)
            except AddrFormatError:
                t = target
        if type(t) == IPNetwork or type(t) == IPRange:
            return [str(i) for i in list(t)]
        else:
            return [t.strip()]

        return [target]
    else:
        try:
            with open(target, 'r', encoding='utf8') as reader:
                targets = reader.read().replace('\r', '').replace(' ', '').split('\n')
            targets = [i for i in targets if i != '']

            return targets
        except:
            logger.error(f"Failed to parse file {target}, try to change file encoding to utf-8")


def is_ip(target=None):
    return re.match(r'^\d+\.\d+\.\d+\.\d+$', target)


def resolve_ip_by_nslookup(target):
    """
    This function is used to get IP of FQDN by dns query
    :param target: any FQDN
    :return:
    """
    try:
        my_resolver = dns.resolver.Resolver()
        #TODO:
        # remove this and add ability to sec custom
        # my_resolver.nameservers = ['10.60.4.161']
        resolved = my_resolver.resolve(target, 'A')[0].to_text()
        return resolved
    except Exception as e:
        tqdm.tqdm.write(Fore.LIGHTRED_EX + f"Failed to resolve: {target}")
        return None


# def get_shares_for_host(host=None)

def resolve_target(thread_db, thread_sql, target=None):
    """
    This function determines is target is ip or FQDN and then
    tries to determine target's IP (if target = FQDN)
    :param target: ip or FQDN
    :return: ip
    """
    if is_ip(target):
        db_insert_host(thread_db, thread_sql, ip=target, hostname=None)
        return target
    else:
        target = target.lower()

        # TODO remove this comment
        resolved = get_ip_from_db_by_hostname(thread_sql, hostname=target)
        resolved = None
        if not resolved:
            resolved = resolve_ip_by_nslookup(target=target)
            if resolved == None:
                # tqdm.tqdm.write(Fore.LIGHTYELLOW_EX + f'Failed to resolve {target}')
                not_resolved.append(target)
            # TODO and this
            else:
                db_insert_host(thread_db, thread_sql, ip=resolved, hostname=target)

        return resolved


def get_list_of_shares_from_db_for_host(target=None):
    if is_ip(target):
        query = f"SELECT share_name FROM shares where ip='{target}'"
    else:
        query = f"SELECT share_name FROM shares where hostname like '{target.split('.')[0]}'"
    sql.execute(query)
    result = sql.fetchall()
    if result:
        result = [i[0] for i in result]
    return result


def list_shares(db, sql, connection=None, depth=4, username=None, password=None, user_domain=None, reconnect=0,
                timeout=5, thread_index=0):
    try:  # what if

        connection.login(username, password, user_domain)  # , lmhash, nthash)

        host_info = db_update_host_info_using_connection(db, sql, connection)

        target_ip = connection.getRemoteHost()
        if not target_ip:  # sometimes unknown shit happens
            raise
        # if host_info['host_domain'].lower() != user_domain.lower():
        #     tqdm.tqdm.write(Fore.LIGHTYELLOW_EX +
        #                     f"Thr {thread_index} - Host's {host_info['hostname']} ({host_info['ip']}) domain ({host_info['host_domain']}) not in users domain ({user_domain}), skipping...")
        #     return
        # db_update_host_info_using_connection(db, sql, connection)

        # logger.info(
        #     f'Authorized on {host_info["host_domain"]}\\{host_info["hostname"]} ({target_ip}) as {user_domain}\\{username}')
        shares = get_shares(db, sql, connection)
        if username == '':
            tqdm.tqdm.write(
                Fore.LIGHTGREEN_EX + f"Null session exists on {connection.getServerName() + ('.' + host_info['host_domain'] if host_info['host_domain'] else '')} ({host_info['ip']})")

        # tqdm.tqdm.write(shares)
        bad_shares = ['ADMIN$', 'IPC$','C$']
        tqdm.tqdm.write(
                Fore.LIGHTYELLOW_EX + f"\nFound shares on {connection.getServerName() + ('.' + host_info['host_domain'] if host_info['host_domain'] else '')} ({host_info['ip']}):\n" \
                    + Fore.LIGHTGREEN_EX
                    + '\n'.join([share for share in shares]) + '\n')

        shares = [share for share in shares if share not in bad_shares]
        for share in shares:
            try:
                connection.listPath(share, '*')  # if exception - no READ access
                if share == 'C$' or share == 'C':
                    tqdm.tqdm.write(
                        Fore.LIGHTGREEN_EX + f"C$ is available on {connection.getServerName() + '.' + host_info['host_domain']} ({host_info['ip']})")
                elif share == 'print$':
                    continue
                _spider(db, sql, connection, share, '.', depth)
            except Exception as e:
                #TODO:debug log about shares and errors
                continue

    except Exception as e:
        host_info = db_update_host_info_using_connection(db, sql, connection)
        target = connection.getServerName().lower() + '.' + host_info['host_domain']
        target_ip = connection.getRemoteHost()
        connection.close()
        # TODO: normal exceptions proceeding
        if 'STATUS_ACCESS_DENIED' in str(e):
            tqdm.tqdm.write(Fore.LIGHTYELLOW_EX +
                            f"Thr {thread_index} - STATUS_ACCESS_DENIED on " + (
                                f'{target} ({target_ip})' if target != target_ip else target))
            return
        elif 'STATUS_INVALID_PARAMETER' in str(e):
            tqdm.tqdm.write(Fore.LIGHTYELLOW_EX +
                            f"Thr {thread_index} - STATUS_INVALID_PARAMETER on " + (
                                f'{target} ({target_ip})' if target != target_ip else target))
            return
        elif 'STATUS_LOGON_TYPE_NOT_GRANTED' in str(e):
            tqdm.tqdm.write(Fore.LIGHTYELLOW_EX +
                            f"Thr {thread_index} - STATUS_LOGON_TYPE_NOT_GRANTED on " + (
                                f'{target} ({target_ip})' if target != target_ip else target))
            return
        elif 'STATUS_LOGON_FAILURE' in str(e):
            tqdm.tqdm.write(Fore.LIGHTYELLOW_EX +
                            f"Thr {thread_index} - STATUS_LOGON_FAILURE on " + (
                                f'{target} ({target_ip})' if target != target_ip else target))
            return


        tqdm.tqdm.write(Fore.LIGHTYELLOW_EX +
                        f"Thr {thread_index} - Exceptions while listing shares on {target} - {target_ip}{(', reconnect №' + str(reconnect)) if reconnect != 0 else ''}\n"
                        f"{Fore.LIGHTRED_EX} + {str(e)}")

        if reconnect >= 5:
            tqdm.tqdm.write(Fore.LIGHTYELLOW_EX +
                            f"Thr {thread_index} - Failed to reconnect to {target} - {target_ip} for 5 times")
            return
        else:
            time.sleep(5)
            connection = make_connection(db, sql, address=target, target_ip=target_ip, port=445,
                                         do_not_login=True, timeout=timeout + 2, thread_index=thread_index)
            if not connection:
                return
            list_shares(db, sql, connection=connection, username=username, password=password, user_domain=user_domain,
                        reconnect=reconnect + 1, timeout=timeout + 2, thread_index=thread_index)

    # except Exception as e:
    #     target = connection.getServerName().lower() + '.' + domain
    #     target_ip = connection.getRemoteHost()
    #     tqdm.tqdm.write(f"Exception while listing shares on {target}\t{target_ip}")
    #     tqdm.tqdm.write(e)


def win_timestamp_to_date(timestamp):
    value = datetime.datetime(1601, 1, 1) + datetime.timedelta(seconds=timestamp / 10000000)
    return value.strftime('%d-%m-%Y %H:%M:%S')


def _spider(db, sql, connection, share, subfolder, depth):
    """
    Recursion function for crawlind share folders
    original function took from crackmapexec and refactored
    :param db:          sqlite db object
    :param sql:         sql cursor
    :param connection:  impacket SMB connection object
    :param share:       share name
    :param subfolder:   subfolder
    :param depth:       max depth
    :return:            nothing
    """
    if depth == 0:
        return
    # ToDO exclude windows folder
    if share == 'C$' or share == 'C':
        if subfolder in ['.']:
            depth = 2
        elif subfolder.lower() == 'windows':
            depth = 1
        elif subfolder.lower() == 'users':
            depth = 3

    if subfolder in ['', '.']:
        subfolder = '*'

    elif subfolder.startswith('*/'):
        subfolder = subfolder[2:] + '/*'
    else:
        subfolder = subfolder.replace('/*/', '/') + '/*'

    # End of the funky shit... or is it? Surprise! This whole thing is funky

    filelist = None
    try:
        filelist = connection.listPath(share, subfolder)  # files and dirs

    except SessionError as e:  # no access or whatever
        return

    for result in filelist:
        file_longname = result.get_longname()
        if file_longname in ['.', '..']:
            continue

        file_kwargs = {}
        file_kwargs['ip'] = connection.getRemoteHost()
        file_kwargs['share_name'] = share
        file_kwargs['parent_folder'] = subfolder.replace('*', '')
        file_kwargs['filename'] = file_longname
        file_kwargs['creation_date'] = win_timestamp_to_date(result.get_ctime())
        file_kwargs['ctime'] = result.get_ctime()
        file_kwargs['modification_date'] = win_timestamp_to_date(result.get_mtime())
        file_kwargs['mtime'] = result.get_mtime()

        if result.is_directory():
            file_kwargs['is_file'] = 0
            db_insert_share_content(db, sql, **file_kwargs)

            if subfolder == '*':
                # db_insert_share_content()
                _spider(db, sql, connection, share, subfolder.replace('*', '') + file_longname,
                        depth - 1 if depth else None)
            elif subfolder != '*' and (subfolder[:-2].split('/')[-1] not in []):  # exclude_dirs):
                _spider(db, sql, connection, share, subfolder.replace('*', '') + file_longname,
                        depth - 1 if depth else None)
        else:
            file_kwargs['is_file'] = 1
            file_kwargs['file_size'] = result.get_filesize()
            file_kwargs['extension'] = file_longname.split('.')[-1] if len(file_longname.split('.')) >= 2 else None
            db_insert_share_content(db, sql, **file_kwargs)
    return

def thread_worker(thread_index=0):
    thread_db = sqlite3.connect(f'database_thread{thread_index}.db')
    thread_sql = thread_db.cursor()
    # db_init(thread_db, thread_sql)

    for target_index in tqdm.tqdm(range(len(threads_targets[thread_index])),
                                  desc=Fore.LIGHTYELLOW_EX + f"Thread {thread_index} ",
                                  leave=False, unit="target"):

        target = threads_targets[thread_index][target_index]
        # target - original target's ip or resolved ip from if target = fqdn

        connection_kwargs = {}

        if is_ip(target):
            connection_kwargs['target_ip'] = target
            connection_kwargs['address'] = target
        else:
            resolved_target = resolve_target(thread_db, thread_sql, target=target)
            if resolved_target == None:
                # logger.error(f"Failed to resolve target {target}")
                continue

            connection_kwargs['target_ip'] = resolved_target
            connection_kwargs['address'] = target

        connection_kwargs['user_domain'] = args['domain']
        connection_kwargs['thread_index'] = thread_index

        connection = make_connection(thread_db, thread_sql, **connection_kwargs)
        # make_connection returns None if not connected
        if not connection:
            continue

        login_kwargs = {}
        login_kwargs['connection'] = connection
        login_kwargs['username'] = args['username']

        login_kwargs['user_domain'] = args['domain']  # .split('.')[0].upper()
        login_kwargs['password'] = args['password']
        login_kwargs['depth'] = args['depth']
        login_kwargs['thread_index'] = thread_index

        list_shares(thread_db, thread_sql, **login_kwargs)
    thread_db.close()


def db_merger(thread_count):
    for thread_index in range(thread_count):
        main_db = sqlite3.connect('database.db')
        main_sql = main_db.cursor()

        thread_db = sqlite3.connect(f'database_thread{thread_index}.db')
        thread_sql = thread_db.cursor()

        new_hosts = thread_sql.execute(
            f'select host_id,ip,hostname,domain,os,os_build,port_445_is_open,port_139_is_open from hosts').fetchall()
        for host in new_hosts:
            try:
                host_ip = host[1]
                old_host_id = host[0]
                main_sql.execute(
                    f'INSERT into hosts(ip,hostname,domain,os,os_build,port_445_is_open,port_139_is_open) VALUES (?,?,?,?,?,?,?)',
                    host[1:])
                main_db.commit()

                new_host_id = main_sql.execute(f'SELECT host_id FROM hosts WHERE ip = "{host_ip}"').fetchone()[0]
                old_shares = thread_sql.execute(
                    f'select share_id, host_id,share_name,share_remark,empty_cred_access,guest_cred_access from shares where host_id = {old_host_id}').fetchall()
                for share in old_shares:
                    old_share_id = share[0]
                    share = list(share)
                    share[1] = new_host_id
                    share = tuple(share[1:])
                    try:
                        main_sql.execute(
                            f'INSERT INTO shares(host_id,share_name,share_remark,empty_cred_access,guest_cred_access) VALUES (?,?,?,?,?)',
                            share)
                    except Exception as e:
                        print("Exception on inserting share")
                        print(e)

                    main_db.commit()
                    new_share_id = main_sql.execute(
                        f'SELECT share_id from shares WHERE host_id={new_host_id} AND share_name="{share[1]}"').fetchone()[
                        0]

                    old_files = thread_sql.execute(
                        f'SELECT share_id,parent_folder,filename,is_file,extension,file_size,creation_date,modification_date,ctime,mtime FROM share_content WHERE share_id = {old_share_id}').fetchall()

                    for file in old_files:
                        file = list(file)
                        file[0] = new_share_id
                        file = tuple(file)
                        try:
                            main_sql.execute(
                                f'INSERT INTO share_content(share_id,parent_folder,filename,is_file,extension,file_size,creation_date,modification_date,ctime,mtime) VALUES (?,?,?,?,?,?,?,?,?,?)',
                                file)
                        except Exception as e:
                            print("Exception on inserting file")
                            print(e)
                    main_db.commit()
            except Exception as e:
                pass
        main_db.commit()
        thread_sql.close()
        thread_db.close()
        os.remove(f"database_thread{thread_index}.db")


def gen_xlsx():
    db = sqlite3.connect('database.db')
    sql = db.cursor()

    workbook = xlsxwriter.Workbook("smbsniper_" + datetime.datetime.now().strftime("%d.%m.%Y %H-%M") + '.xlsx')
    worksheet = workbook.add_worksheet("smbsniper")
    for column_number, column_name in enumerate(sql.execute("PRAGMA table_info('full');")):
        worksheet.write(0, column_number, column_name[1])

    for row_number, row in enumerate(sql.execute('SELECT * FROM full')):
        for column_number, item in enumerate(row):
            worksheet.write(row_number + 1, column_number, item)
    workbook.close()


if __name__ == '__main__':

    start = time.time()

    db_init(db, sql, close=True)

    get_args()

    targets = parse_target_arg(args['address'])

    # targets = get_targets(args['address'])

    if not targets:
        print(Fore.LIGHTRED_EX + "No targets, exiting")
        sys.exit(1)

    threads_lists = []
    threads_count = args['threads']

    threads_targets = []  # list of lists of targets

    targets_count = len(targets)
    if targets_count < threads_count:
        threads_count = targets_count

    targets_per_thread_count = int(math.ceil(targets_count / threads_count))

    # Targets separation for thread's list of targets
    for i in range(0, targets_count, targets_per_thread_count):
        threads_targets.append(targets[i:i + targets_per_thread_count])

    # Threads init
    for thread_index in range(threads_count):
        # every thread have copy of database.db
        # copies will be merged back to database.db at the end
        # when I was writing it, I didn't know queues, make pull request if u want
        shutil.copyfile('database.db', f'database_thread{thread_index}.db')

        thread_kwargs = {'thread_index': thread_index}

        t = threading.Thread(target=thread_worker,
                             kwargs=thread_kwargs)
        threads_lists.append(t)
        t.start()

    for t in threads_lists:
        try:
            t.join()
        except KeyboardInterrupt:
            exit()

    if len(not_resolved) != 0:
        with open('failed_to_resolve.txt', 'w', encoding='utf8') as writer:
            writer.write("\n".join(not_resolved))
    if len(closed_445) != 0:
        with open('445_closed.txt.txt', 'w', encoding='utf8') as writer:
            writer.write("\n".join(closed_445))

    end = time.time()
    print(Fore.LIGHTYELLOW_EX + "[=] Took time: {:.3f} min\n\n".format((end - start) / 60))

    db_merger(threads_count)
    try:
        import xlsxwriter

        gen_xlsx()
    except:
        print(Fore.LIGHTRED_EX + "You need to install XlsxWriter to generate xlsx files")
    # print()
