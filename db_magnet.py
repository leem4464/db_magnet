import argparse
import json
import os
import requests
import sys
from prettytable import PrettyTable
from database import DATABASES, FILE_SERVERS
from utils import send_email, make_email_text


URL = 'https://api.criminalip.io/v1/ip/data'


def find_criminalip(api_key, ip, category, target=None):
    params = {'ip': ip}
    headers = {'x-api-key': api_key}

    result = requests.get(url=URL, params=params, headers=headers)
    result = result.json()

    ports = set()
    if category == 'database':
        for k, v in DATABASES.items():
            for x in v:
                ports.add(x)
    elif category == 'file_server':
        for k, v in FILE_SERVERS.items():
            for x in v:
                ports.add(x)

    founded_db = []
    for r in result['port']['data']:
        if r['open_port_no'] in ports:
            r['ip'] = ip

            vuln = []
            for v in result['vulnerability']['data']:
                if v['app_name'] == r['app_name'] and v['app_version'] == r['app_version']:
                    vuln.append(v['cve_id'])

            r['vuln'] = vuln

            founded_db.append(r)

    if target == 'one':
        return [founded_db]
    else:
        return founded_db


def show(founded_db):
    pt = PrettyTable()
    pt.field_names = ['IP', 'port', 'app_name', 'app_version', 'scanned_time', 'vulnerability']

    for x in founded_db:
        for f in x:
            vuln = '\n'.join([v for v in f['vuln']])
            pt.add_row([f['ip'], f['open_port_no'], f['app_name'], f['app_version'], f['confirmed_time'], vuln])

    print(pt)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Find database by using criminalip service')
    parser.add_argument('--api_key', help='criminalip api key')
    parser.add_argument('--ip', help='IP')
    parser.add_argument('--file', help='scan a file')
    parser.add_argument('--category', help='category (ex: database, file_server)')
    parser.add_argument('--email', help='send result to an email')

    args = parser.parse_args()

    # API key
    path = os.getcwd()
    if args.api_key:
        api_key = args.api_key

        if os.path.isfile('{}/.api_key'.format(path)):
            x = input('Do you want to update your api_key? (Y/n) ')
            if x in ['y', 'Y']:
                with open('{}/.api_key'.format(path), 'w') as file:
                    file.write(api_key)
                print('\nSuccessfully updated\n')
            else:
                print('\nCanceled\n')
        else:
            with open('{}/.api_key'.format(path), 'w') as file:
                file.write(api_key)
    else: #
        with open('{}/.api_key'.format(path), 'r') as file:
            api_key = file.readline().strip()

    # IP Scan
    if args.ip and args.category:
        founded_db = find_criminalip(api_key, args.ip, args.category, 'one')

        show(founded_db)

    # File scan
    elif args.file and args.category:
        founded_db = []
        with open('{}/{}'.format(path, args.file), 'r') as file:
            lines = file.readlines()
            for l in lines:
                ip = l.strip()
                res = find_criminalip(api_key, ip, args.category)

                founded_db.append(res)

        show(founded_db)

    # Send e-mail
    if args.email in ['Y', 'y']:
        if os.path.isfile('{}/.email_info'.format(path)):
            with open('.email_info', 'r') as file:
                email_info = {}
                lines = file.readlines()

                for l in lines:
                    k = l.split(':')[0].strip()
                    v = l.split(':')[1].strip()
                    email_info[k] = v
        else:
            account = input('Enter email account : ')
            passwd = input('Enter email password : ')
            host = input('Enter email host : ')
            port = input('Enter email port : ')
            send_to = input('Enter email address you want to send to : ')

            with open('.email_info', 'w') as file:
                file.write('account : {}\n'.format(account))
                file.write('passwd : {}\n'.format(passwd))
                file.write('host : {}\n'.format(host))
                file.write('port : {}\n'.format(port))
                file.write('send_to : {}\n'.format(send_to))

            email_info = {
                'account': account,
                'passwd': passwd,
                'host': host,
                'port': port,
                'send_to': send_to,
            }

        subject, email_text = make_email_text(founded_db)
        send_email(email_info, subject, email_text)
