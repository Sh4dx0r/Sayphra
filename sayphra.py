from shutil import which
from shodan import Shodan
from colorama import Fore, Back, Style
from os import path, mkdir
from builtwith import builtwith
from modules.favicon import *
from bs4 import BeautifulSoup
from multiprocessing.pool import ThreadPool
import multiprocessing
import re
from alive_progress import alive_bar
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.exceptions import RequestException
import os.path
from modules import user_agents
import socket
import subprocess
import threading
import sys
import socket
import os
import argparse
import time
import codecs
import requests
import mmh3
import urllib3
import warnings

warnings.filterwarnings(action='ignore',module='bs4')

requests.packages.urllib3.disable_warnings()

banner = """
  ██████  ▄▄▄     ▓██   ██▓ ██▓███   ██░ ██  ██▀███   ▄▄▄      
▒██    ▒ ▒████▄    ▒██  ██▒▓██░  ██▒▓██░ ██▒▓██ ▒ ██▒▒████▄    
░ ▓██▄   ▒██  ▀█▄   ▒██ ██░▓██░ ██▓▒▒██▀▀██░▓██ ░▄█ ▒▒██  ▀█▄  
  ▒   ██▒░██▄▄▄▄██  ░ ▐██▓░▒██▄█▓▒ ▒░▓█ ░██ ▒██▀▀█▄  ░██▄▄▄▄██ 
▒██████▒▒ ▓█   ▓██▒ ░ ██▒▓░▒██▒ ░  ░░▓█▒░██▓░██▓ ▒██▒ ▓█   ▓██▒
▒ ▒▓▒ ▒ ░ ▒▒   ▓▒█░  ██▒▒▒ ▒▓▒░ ░  ░ ▒ ░░▒░▒░ ▒▓ ░▒▓░ ▒▒   ▓▒█░
░ ░▒  ░ ░  ▒   ▒▒ ░▓██ ░▒░ ░▒ ░      ▒ ░▒░ ░  ░▒ ░ ▒░  ▒   ▒▒ ░
░  ░  ░    ░   ▒   ▒ ▒ ░░  ░░        ░  ░░ ░  ░░   ░   ░   ▒   
      ░        ░  ░░ ░               ░  ░  ░   ░           ░  ░
                   ░ ░                                         
Author: Sh4dx0r                                                           
Version: v1.5
"""

print(Fore.CYAN + banner)
print(Fore.WHITE)

def commands(cmd):
    try:
        subprocess.check_call(cmd, shell=True)
    except:
        pass

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()

vuln_group = parser.add_argument_group('Vulnerability')
fuzzing_group = parser.add_argument_group('Fuzzing')

group.add_argument('-sv', '--save', action='store',
                   help="Save output to a file",
                   metavar="filename.txt")

parser.add_argument('-s',
                    type=str, help='Scan for Subdomains',
                    metavar='domain.com')

parser.add_argument('-d', '--dns',
                    type=str, help='Scan for DNS records',
                    metavar='domain.com')

parser.add_argument('-p', '--probe',
                    type=str, help='Probe Domains.',
                    metavar='domains.txt')                    

parser.add_argument('-df', '--directoryforce',
                    type=str, help='Brute force filenames and directories',
                    metavar='domain.com')                    

fuzzing_group.add_argument('-wl', '--wordlist', action='store',
                   help="wordlist to use",
                   metavar="filename.txt")

parser.add_argument('-th', '--threads',
                    type=str, help='default 25',
                    metavar='25')                    

fuzzing_group.add_argument("-e", "--extensions", help="Comma-separated list of file extensions to scan", default="")

fuzzing_group.add_argument("-c", "--exclude", help="Comma-separated list of status codes to filter", default="")

parser.add_argument('-wc', '--webcrawler',
                    type=str, help='Scan for urls and js files',
                    metavar='https://domain.com')

parser.add_argument('-fi', '--favicon',
                    type=str, help='Get favicon hashes',
                    metavar='https://domain.com')

parser.add_argument('-fm', '--faviconmulti',
                    type=str, help='get favicon hashes',
                    metavar='https://domain.com')

parser.add_argument('-na', '--networkanalyzer',
                    type=str, help='Net Analyzer',
                    metavar='https://domain.com')

parser.add_argument('-sh', '--securityheaders',
                    type=str, help='Scan for Security Headers',
                    metavar='domain.com')

parser.add_argument('-ed', '--enumeratedomain',
                    type=str, help='enumerate domains',
                    metavar='domain.com')

parser.add_argument('-ips', '--ipaddresses',
                    type=str, help='get the ips from a list of domains',
                    metavar='domain list')


args = parser.parse_args()

user_agent = user_agents.get_useragent()
header = {"User-Agent": user_agents}

if args.s:
    if args.save:
        print(Fore.CYAN + "Saving output to {}...".format(args.save))
        cmd = f"./scripts/spotter.sh {args.s} | uniq | sort"
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        spotterout, err = p.communicate()
        spotterout = spotterout.decode()
        with open(f"{args.save}", "a") as spotter:
            spotter.writelines(spotterout)
        cmd = f"./scripts/certsh.sh {args.s} | uniq | sort"
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        certshout, err = p.communicate()
        certshout = certshout.decode()
        with open(f"{args.save}", "a") as certsh:
            certsh.writelines(certshout)
    else:
        commands(f"./scripts/spotter.sh {args.s} | uniq | sort")
        commands(f"./scripts/certsh.sh {args.s} | uniq | sort") 

def is_valid_domain(domain):
    # Basic regex pattern to check for valid domain format
    pattern = re.compile(r'^(?:http://|https://)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
    return pattern.match(domain)

def domain_works(domain):
    try:
        response = requests.get(domain, timeout=5)
        return response.status_code == 200
    except RequestException:
        return False

if args.webcrawler:
    # Check if the domain starts with 'http://' or 'https://'
    if not args.webcrawler.startswith(('http://', 'https://')):
        webcrawler_url = 'https://' + args.webcrawler
    else:
        webcrawler_url = args.webcrawler
    
    # Validate the domain format
    if not is_valid_domain(webcrawler_url):
        print(Fore.RED + "Please enter a valid domain.")
    elif 'www' in webcrawler_url and not domain_works(webcrawler_url):
        print(Fore.RED + "Domain contains 'www' but is not working. Please enter a valid domain.")
    else:
        if args.save:
            print(Fore.CYAN + f"Saving output to {args.save}")
            commands(f"echo {webcrawler_url} | hakrawler >> {args.save}")
        else:
            commands(f"echo {webcrawler_url} | hakrawler")

if args.favicon:
    # Check if the domain starts with 'http://' or 'https://'
    if not args.favicon.startswith(('http://', 'https://')):
        # Prepend 'https://' if not present
        domain_with_protocol = 'https://' + args.favicon
    else:
        domain_with_protocol = args.favicon

    try:
        # Fetch the favicon from the domain
        response = requests.get(f'{domain_with_protocol}/favicon.ico', verify=False)
        # Encode the favicon content in base64
        favicon = codecs.encode(response.content, "base64").decode().strip()
        # Calculate the hash of the favicon
        hash = mmh3.hash(favicon)
        print(hash)
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}Error fetching favicon: {e}")

if args.enumeratedomain:
    domain = args.enumeratedomain
    
    # Ensure the domain starts with 'https://'
    if not domain.startswith("https://"):
        if domain.startswith("http://"):
            domain = domain.replace("http://", "https://", 1)
        else:
            domain = f"https://{domain}"
    
    server = []
    r = requests.get(domain, verify=False)
    
    # Remove scheme to extract the domain name for IP resolution
    domain = domain.replace("https://", "").replace("http://", "")
    
    ip = socket.gethostbyname(domain)
    for value, key in r.headers.items():
        if value.lower() == "server":
            server.append(key)
    
    if server:
        print(f"{Fore.WHITE}{args.enumeratedomain}{Fore.MAGENTA}: {Fore.CYAN}[{ip}] {Fore.WHITE}Server:{Fore.GREEN} {server}")
    else:
        print(f"{Fore.WHITE}{args.enumeratedomain}{Fore.MAGENTA}: {Fore.CYAN}[{ip}]")

if args.probe:
    if args.save:
        print(Fore.CYAN + "Saving output to {}...".format(args.save))
        commands(f'cat {args.probe} | httprobe -c 100 | anew >> {args.save}')
        if path.exists(f"{args.save}"):
            print(Fore.GREEN + "DONE!")
        if not path.exists(f"{args.save}"):
            print(Fore.RED + "ERROR!")
    else:
        commands(f'sudo cat {args.probe} | httprobe | anew')        

# Function to ensure the domain starts with 'https://'
def ensure_https(domain: str) -> str:
    if not domain.startswith('https://'):
        domain = 'https://' + domain
    return domain

if args.directoryforce:
    if args.wordlist:
        if args.threads:
            def filter_wordlist(wordlist, extensions):
                """
                Filters the wordlist based on the provided extensions.
                If no extensions are provided, returns the original wordlist.
                """
                if not extensions:
                    return wordlist
                ext_list = [ext.strip() for ext in extensions.split(',')]
                return [word for word in wordlist if any(word.endswith(ext) for ext in ext_list)]

            def dorequests(wordlist: str, base_url: str, headers: dict, is_file_only: bool, excluded_codes: set, bar, print_lock):
                """
                Makes HTTP requests for each word in the wordlist and prints results.
                """
                s = requests.Session()  # Create a requests session for making HTTP requests
                
                def check_and_print(url, type_str):
                    """
                    Checks the URL and prints the status code and type of resource found.
                    """
                    try:
                        r = s.get(url, verify=False, headers=headers, timeout=10)  # Perform GET request
                        if r.status_code not in excluded_codes:  # Check if status code is not in excluded codes
                            # Set colors based on status code
                            if r.status_code == 200:
                                status_code_color = Fore.GREEN
                                url_color = Fore.GREEN
                            elif r.status_code in {404, 400, 403}:
                                status_code_color = Fore.RED
                                url_color = Fore.RED
                            else:
                                status_code_color = Fore.YELLOW
                                url_color = Fore.YELLOW  # Default color for other status codes
                                
                            with print_lock:
                                # Print the status code and URL with respective colors
                                print(f"{status_code_color}[{r.status_code}]{Fore.RESET} {Fore.WHITE}{type_str} Found: {url_color}{url}{Fore.RESET}")
                    except requests.RequestException:
                        pass
                    finally:
                        bar()  # Update the progress bar

                # Form URL based on whether checking for files or directories
                if is_file_only:
                    url = f"{base_url}/{wordlist}"
                    check_and_print(url, "File")
                else:
                    dir_url = f"{base_url}/{wordlist}/"
                    check_and_print(dir_url, "Directory")
                    
            def main():
                """
                Main function that handles reading the wordlist, filtering, and making requests.
                """
                # Ensure the target URL starts with 'https://'
                args.directoryforce = ensure_https(args.directoryforce)
                
                with open(args.wordlist, "r") as f:
                    wordlist_ = [x.strip() for x in f.readlines()]  # Read and clean wordlist
                
                is_file_only = bool(args.extensions)  # Determine if only files are to be checked
                
                filtered_wordlist = filter_wordlist(wordlist_, args.extensions)  # Filter wordlist based on extensions
                
                excluded_codes = set(int(code.strip()) for code in args.exclude.split(',') if code.strip())  # Parse excluded status codes
                
                # Print initial information
                print(f"Target: {Fore.CYAN}{args.directoryforce}{Fore.RESET}\n"
                      f"Wordlist: {Fore.CYAN}{args.wordlist}{Fore.RESET}\n"
                      f"Extensions: {Fore.CYAN}{args.extensions or 'All'}{Fore.RESET}\n"
                      f"Filtered Status Codes: {Fore.RED}{', '.join(map(str, excluded_codes)) or 'None'}{Fore.RESET}\n")

                headers = {'User-Agent': user_agent}  # Set headers for requests

                print_lock = threading.Lock()  # Create a lock to ensure thread-safe printing

                with alive_bar(len(filtered_wordlist), title="Scanning", bar="classic", spinner="classic") as bar:
                    with ThreadPoolExecutor(max_workers=int(args.threads)) as executor:
                        # Submit tasks to the thread pool for each word in the filtered wordlist
                        futures = [executor.submit(dorequests, wordlist, args.directoryforce, headers, is_file_only, excluded_codes, bar, print_lock) 
                                   for wordlist in filtered_wordlist]
                        
                        for future in as_completed(futures):
                            future.result()  # Wait for all tasks to complete

            if __name__ == "__main__":
                main()

                
if args.faviconmulti:
    print(f"{Fore.MAGENTA}\t\t\t FavIcon Hashes\n")
    with open(f"{args.faviconmulti}") as f:
        domains = [x.strip() for x in f.readlines()]
        try:
            for domainlist in domains:
                # Ensure the domain starts with 'http://' or 'https://'
                if not domainlist.startswith("http://") and not domainlist.startswith("https://"):
                    domainlist = "http://" + domainlist  # Default to http://

                response = requests.get(f'{domainlist}/favicon.ico', verify=False, timeout=60)
                if response.status_code == 200:
                    favicon = codecs.encode(response.content,"base64")
                    hash = mmh3.hash(favicon)
                    hashes = {}
                response = requests.get(f'{domainlist}/favicon.ico', verify=False, timeout=5)
                if response.status_code == 200:
                    favicon = codecs.encode(response.content,"base64")
                    hash = mmh3.hash(favicon)
                    if "https" in domainlist:
                        domainlist = domainlist.replace("https://", "")
                    if "http" in domainlist:
                        domainlist = domainlist.replace("http://", "")
                    ip = socket.gethostbyname(domainlist)
                    if hash == "0":
                        pass
                    for value, item in fingerprint.items():
                        if hash == value:
                            hashes[hash].append(item)
                            print(f"{Fore.WHITE}{domainlist} {Fore.MAGENTA}: {Fore.CYAN}[{hash}] {Fore.GREEN}[{ip}]{Fore.YELLOW} [{item}]")  
                    print(f"{Fore.WHITE}{domainlist} {Fore.MAGENTA}: {Fore.CYAN}[{hash}] {Fore.GREEN}[{ip}]{Fore.YELLOW}")
                    for v,i in hashes.items():
                        print(f"{Fore.MAGENTA}Servers Found")
                        print()
                        print(f"{v}:{i}")
                    else:
                        print(f"{Fore.WHITE}{domainlist} {Fore.MAGENTA}: {Fore.CYAN}{hash} {Fore.GREEN}{ip}")
                else:
                    pass
        except TimeoutError:
            pass
        except requests.exceptions.ConnectionError:
            pass
        except urllib3.exceptions.ProtocolError:
            pass
        except requests.exceptions.ReadTimeout:
            pass
        except KeyError:
            pass


if args.securityheaders:
    domain_url = args.securityheaders
    
    # Ensure the domain starts with 'https://'
    if not domain_url.startswith("https://"):
        domain_url = f"https://{domain_url}"

    print(f"{Fore.MAGENTA}\t\t Security Headers\n")
    security_headers = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection"]
    session = requests.Session()
    no_sec = []
    found_hd = []
    no_dup = []
    no_dup_found = []
    lower = [x.lower() for x in security_headers]
    capital = [x.upper() for x in security_headers]
    resp = session.get(f"{domain_url}", verify=False)
    print(f"{Fore.MAGENTA}Domain: {Fore.WHITE}{domain_url}\n")
    for item, key in resp.headers.items():
        for sec_headers in security_headers:
            if sec_headers == item or item.lower() == sec_headers.lower() or item.upper() == sec_headers.upper():
                found_hd.append(sec_headers)
                [no_dup_found.append(x) for x in found_hd if x not in no_dup_found]
        print(f"{Fore.MAGENTA}{item}: {Fore.WHITE}{key}")
    no_dup = ", ".join(no_dup)
    print(lower)
    print("\n")
    print(f"{Fore.MAGENTA} Found Security Headers: {Fore.WHITE} {len(no_dup_found)}\n")
    no_dup_found = ", ".join(no_dup_found)
    print(f"{Fore.WHITE} {no_dup_found}\n")
    no_headers = [item for item in security_headers if item not in no_dup_found]
    print(f"{Fore.RED} Found Missing headers: {Fore.WHITE} {len(no_headers)}\n")
    no_headers = ", ".join(no_headers)
    print(f"{Fore.WHITE} {no_headers}")



if args.networkanalyzer:
    print(f"{Fore.MAGENTA}\t\t Analyzing Network Vulnerabilities \n")
    print(f"{Fore.CYAN}IP Range: {Fore.GREEN}{args.networkanalyzer}\n")
    print(f"{Fore.WHITE}")
    commands(f"shodan stats --facets port net:{args.networkanalyzer}")
    commands(f"shodan stats --facets vuln net:{args.networkanalyzer}")

if args.dns:
    if args.save:
        print(Fore.CYAN + "Saving output to {}...".format(args.save))
        commands(f"cat {args.dns} | dnsx -silent -a -resp >> {args.save}")
        commands(f"cat {args.dns} | dnsx -silent -ns -resp >> {args.save}")
        commands(f"cat {args.dns} | dnsx -silent -cname -resp >> {args.save}")
    else:
        print(Fore.CYAN + "Printing A records...\n")
        time.sleep(2)
        commands(f"cat {args.dns} | dnsx -silent -a -resp\n")
        print(Fore.CYAN + "Printing NS Records...\n")
        time.sleep(2)
        commands(f"cat {args.dns} | dnsx -silent -ns -resp\n")
        print(Fore.CYAN + "Printing CNAME records...\n")
        time.sleep(2)
        commands(f"cat {args.dns} | dnsx -silent -cname -resp\n")              

if args.ipaddresses:
    with open(f"{args.ipaddresses}", "r") as f:
        domains = [x.strip() for x in f.readlines()]
    
    for domain_list in domains:
        # Remove 'https://' or 'http://' from the beginning of the domain
        if domain_list.startswith("https://"):
            domain_list = domain_list.replace("https://", "", 1)
        elif domain_list.startswith("http://"):
            domain_list = domain_list.replace("http://", "", 1)
        
        try:
            ips = socket.gethostbyname(domain_list)
            print(f"{Fore.GREEN} {domain_list} {Fore.WHITE}- {Fore.CYAN}{ips}")
        except socket.gaierror:
            pass
