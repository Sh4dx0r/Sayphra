
# INSTALLATION

```bash

git clone https://github.com/Sh4dx0r/Sayphra.git

cd Sayphra

pip3 install -r requirements.txt

sudo python3 install.py

```

# USAGE 

```
python sayphra.py [-h] [-sv filename.txt]  [-s domain.com]
                  [-d domains.com]
                  [-wc https://domain.com] [-fi https://domain.com]
                  [-fm https://domain.com] [-na https://domain.com]
                  [-sh domain.com]         [-ed domain.com]
                  [-ips domain list]

options:
  -s, --save: Save output to a file. (e.g., -s example.com -sv output.txt)
  -d, --dns: Scan for DNS records.
  -wc, --webcrawler: Crawl for URLs and JS files.
  -fi, --favicon: Get favicon hash for a single domain.
  -fm, --faviconmulti: Get favicon hashes for multiple domains from a file.
  -na, --networkanalyzer: Analyze network vulnerabilities. need to fix
  -sh, --securityheaders: Scan for security headers.
  -ed, --enumeratedomain: Enumerate domain information.
  -ips, --ipaddresses: Get IPs from a list of domains.                      
```

# EXAMPLE
Scan for subdomains and save the output to a file.
```
python3 sayphra.py -s domain.com --save filename.txt
```
Scan for dns records
```
python3 sayphra.py -d domain.com
```
Scan for FavIcon hashes
```
python3 sayphra.py -fi domain.com
```
Web Crawler
```
python3 sayphra.py -wc https://www.domain.com
```# Sayphra
# Sayphra
