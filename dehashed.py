import json
import requests
import argparse
from fake_useragent import UserAgent
from bs4 import BeautifulSoup
from time import sleep
import os
import sys

dehashed_api_key = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' # Hardcode API key if you so choose
dehashed_username = 'XXXXXXXXXXXXXXXXXXX' # Hardcode email if you so choose
dehashed_default = 'dehashed'

parser = argparse.ArgumentParser()
parser.add_argument('-a', dest='api_key', nargs='?', default=dehashed_api_key, const=dehashed_api_key,
                    help='Use your dehashed.com API key to query domain.')
parser.add_argument('-u', action='store', nargs='?', dest='username', default=dehashed_username, const=dehashed_username,
                    help='Use your dehashed.com username to auth to API.')
parser.add_argument('-d', action='store', dest='domain',
                    help='Target domain to search dehashed.com for.')
parser.add_argument('-f', action='store', dest='dehashed_data_file',
                    help='Read json data from previously saved API query.')
parser.add_argument('-o', action='store', dest='dehashed_file', nargs='?', const=dehashed_default,
                    help='Stores all hashes and cracked passwords in files. [dehashed_*.txt]')
parser.add_argument('--version', action='version', version='%(prog)s 1337.1')
args = parser.parse_args()

def check_api_auth_success(dehashed_json_raw):
    check_success = json.loads(dehashed_json_raw)
    if not check_success.get('success', False):
        sys.exit('[-] API Authentication Failure.')
    else:
        pass

def query_dehashed_domain():
    headers = {'Accept': 'application/json'}
    params = {'query': f'domain:{args.domain}', 'size': 10000} # Add 'size=10000' to fetch more results per query
    dehashed_json_raw = requests.get('https://api.dehashed.com/search',
                            headers=headers,
                            params=params,
                            auth=(args.username, args.api_key)).text
    check_api_auth_success(dehashed_json_raw)
    dehashed_json = jsonify_data(dehashed_json_raw)
    return dehashed_json

def jsonify_data(json_raw_data):
    json_data = json.loads(json_raw_data)
    entries = json_data['entries']
    return entries

def filter_entries(entries):
    password_combos = []
    hash_combos = []
    for entry in entries:
        email = entry['email']
        password = entry['password']
        hash_value = entry['hashed_password']
        if len(password) >= 1:
            combo = email, password
            password_combos.append(combo)
        elif len(hash_value) >= 1:
            combo = email, hash_value
            hash_combos.append(combo)
        else:
            pass
    return password_combos, hash_combos

def output(password_combos, hash_combos):
    print('[+] Cleartext Passwords {email:password}')
    for combo in password_combos:
        combo_raw = f'{combo[0]}:{combo[1]}'
        print(combo_raw)

    print('\n[+] Hashed Passwords {email:hash}')
    for combo in hash_combos:
        combo_raw = f'{combo[0]}:{combo[1]}'
        print(combo_raw)

    print('\n[+] Raw Hashes to Copy/Paste then crack >:)')
    for combo in hash_combos:
        print(combo[1])

    if args.dehashed_file:
        try:
            with open(args.dehashed_file + '_cracked.txt', 'a') as cracked:
                for combo in password_combos:
                    cracked.write(f'{combo[0]}:{combo[1]}\n')

            with open(args.dehashed_file + '_hashes.txt', 'a') as hashes:
                for combo in hash_combos:
                    hashes.write(f'{combo[0]}:{combo[1]}\n')

            print(f'\n[+] Cracked passwords written to {args.dehashed_file}_cracked.txt')
            print(f'[+] Hashes written to {args.dehashed_file}_hashes.txt')
        except Exception as e:
            print('[-] Failed to save the output.')
    else:
        print('[+] Done!')

def check_data_returned(entries):
    if not entries:
        sys.exit('[-] No data returned. Probably an error in syntax.')

def control_flow():
    if args.dehashed_data_file:
        try:
            print('[+] Parsing Dehashed output file...')
            with open(args.dehashed_data_file, 'r') as json_raw_data:
                json_data = json.loads(json_raw_data.read())
            entries = json_data['entries']
            check_data_returned(entries)
            return entries
        except json.decoder.JSONDecodeError:
            sys.exit('[-] Failed to import JSON file.')
    elif args.api_key and args.domain and args.username:
        print('[+] Querying Dehashed for all entries under domain: ' + args.domain + '...')
        entries = query_dehashed_domain()
        return entries
    else:
        sys.exit('[-] Missing argument, exiting.')

if __name__ == '__main__':
    entries = control_flow()
    password_combos, hash_combos = filter_entries(entries)
    output(password_combos, hash_combos)
