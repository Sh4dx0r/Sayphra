# Description

![Sayphra](blob:null/be17f791-45a7-4710-a7fa-63f3dd345a7b)

Sayphra is a powerful tool for network scanning and vulnerability assessment, designed for security professionals and penetration testers. It combines multiple scanning methods and integrates with various external tools to provide detailed insights into networks and web applications.

## Here's a high overview of its functionality

1. Displays a colorful banner.

2. Configures command-line argument parsing for various scanning options.

3. It includes multiple scanning functions for different purposes:
   - Subdomain enumeration
   - DNS record scanning
   - Web crawling and URL extraction
   - Favicon hash calculation
   - Security header analysis
   - Network vulnerability analysis
   - Broken link checking
   - IP address extraction
   - Domain information gathering
   - API endpoint fuzzing
   - Shodan integration for additional recon
   - Directory and file brute-forcing
   - Google dorking

# Installation

To get started with **Sayphra**, follow these steps:

```
git clone https://github.com/Sh4dx0r/Sayphra.git

cd Sayphra

pip3 install -r requirements.txt

sudo python3 install.py
```
---

# Usage
```
python sayphra.py [-h] [-sv filename.txt] [-s domain.com] 
                  [-d domains.com] [-p domains.com] 
                  [-wc https://domain.com] [-fi https://domain.com] 
                  [-fm https://domain.com] [-na https://domain.com] 
                  [-sh domain.com] [-ed domain.com] 
                  [-ips domain list]
```

**Options:**

- **`-s`, `--save`**: Save output to a file. (e.g., `-s example.com -sv output.txt`)
- **`-p`, `--probe`**: Probe subdomains.
- **`-d`, `--dns`**: Scan for DNS records.
- **`-wc`, `--webcrawler`**: Crawl for URLs and JS files.
- **`-fi`, `--favicon`**: Get favicon hash for a single domain.
- **`-fm`, `--faviconmulti`**: Get favicon hashes for multiple domains from a file.
- **`-na`, `--networkanalyzer`**: Analyze network vulnerabilities.
- **`-sh`, `--securityheaders`**: Scan for security headers.
- **`-ed`, `--enumeratedomain`**: Enumerate domain information.
- **`-ips`, `--ipaddresses`**: Get IPs from a list of domains.

---

**Fuzzing:**

- **`-wl filename.txt`, `--wordlist wordlistpath/file.txt`**: Wordlist to use.
- **`-e EXTENSIONS`, `--extensions EXTENSIONS`**: Comma-separated list of file extensions to scan.
- **`-c EXCLUDE`, `--exclude EXCLUDE`**: Comma-separated list of status codes to filter.

---

# Examples

**Scan for subdomains and save the output to a file:**

```bash
python3 sayphra.py -s domain.com --save filename.txt
```

**Scan for DNS records:**

```bash
python3 sayphra.py -d domain.com
```

**Scan for FavIcon hashes:**

```bash
python3 sayphra.py -fi domain.com
```

**Web Crawler:**

```bash
python3 sayphra.py -wc https://www.domain.com
```

**Directory Brute Forcing with no extensions:**

```bash
python3 sayphra.py --directoryforce domain.com --wordlist list.txt --threads 50 -c 404,403
```

**Directory Brute Forcing with extensions:**

```bash
python3 sayphra.py --directoryforce domain.com --wordlist list.txt --threads 50 -e php,txt,html -c 404,403
```
