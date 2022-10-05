![](https://img.shields.io/github/go-mod/go-version/glebarez/cero) ![](https://img.shields.io/codecov/c/github/glebarez/cero) [![build](https://github.com/glebarez/cero/actions/workflows/create-release.yaml/badge.svg)](https://github.com/glebarez/cero/actions/workflows/create-release.yaml)

# cero
Cero will connect to remote hosts, and read domain names from the certificates provided during TLS handshake. <br>
It is not limited to only HTTPS, and will scrape certificates from any protocol that works over TLS (e.g. SMTPS) - just give it the right ports to connect to.<br>
Cero allows flexible specification of targets, including domain names, IP addresses, and CIDR ranges, with full support for IPv6.

## Installation / Update
- Download pre-compiled binary for your OS from [Latest release](https://github.com/glebarez/cero/releases/latest)
- alternatively, compile from source:
```bash
go install github.com/glebarez/cero@latest
```

## Usage examples
Connect to remote host using its domain name and default port (443)
```bash
▶ cero yahoo.com
*.www.yahoo.com
*.yahoo.com
yahoo.com
*.amp.yimg.com
mbp.yimg.com
*.att.yahoo.com
add.my.yahoo.com
ca.my.yahoo.com
ca.rogers.yahoo.com
ddl.fp.yahoo.com
fr-ca.rogers.yahoo.com
hk.rd.yahoo.com
tw.rd.yahoo.com
```
NOTE: You might want to use the **-d** option to automatically strip invalid domain names (e.g. wildcards, bare IPs and usual gibberish) to integrate this tool more smoothly into your recon pipelines.

Cero is fast and concurrent, you can pipe your inputs into it. The concurrency level can be set with **-c** flag:
```bash
cat myTargets.txt | cero -c 1000
```
you can define list of default ports to connect to, with **-p** option:
```bash
cat myTargets.txt | cero -p 443,8443
```
Cero will accept bare IP as input:
```bash
cero 10.0.0.1
```
Or a CIDR range
```bash
cero 10.0.0.1/22
```
IPv6 is fully supported
```bash
cero 2a00:b4c0::/102
```
you can use specific port for every target
```bash
cero 10.0.0.1:8443 [2a00:b4c0::1]:10443
```
Port specification is even supported on CIDR ranges:
```bash
cero 192.1.1.1/16:8443
```
```bash
cero 2a00:b4c0::/102:8443
```
Here is mass-scraping example for popular TLS ports across entire CIDR range:
```
cero -p 443,4443,8443,10443 -c 1000 192.0.0.1/16
```

## Output control
By default, cero will only output successfully scraped domain names as simple list (to standard output), and the errors (if any)  will be suppressed.<br>
If you want to see detailed output for every host, use the **-v** flag. This will format output a little differently, and also write error messages to standard error.
```bash
▶ cero -v example.com example.com:80
example.com:80 -- tls: first record does not look like a TLS handshake
example.com:443 -- [www.example.org example.com example.edu example.net example.org www.example.com www.example.edu www.example.net]
```
For precise controls, use shell redirects:
```
▶ cero -v example.com example.com:80 2>/dev/null
example.com:443 -- [www.example.org example.com example.edu example.net example.org www.example.com www.example.edu www.example.net]
```

## Note on port specification in IPv6 addresses
Text representation of IPv6 address by design contains semicolons (see RFC4291), thus to specify the port you must enclose the host address in square brackets, e.g.:
```
[ff:23::43:1]:443
```
Though this is not mandatory (at least for cero)<br>
In unambiguous cases cero will correctly split the host and port, even when square brackets are not used.<br>In truly ambiguous cases, cero will parse the whole input as IPv6 address.

## Full option list
```console
usage: cero [options] [targets]
if [targets] not provided in commandline arguments, will read from stdin

options:
  -c int
        Concurrency level (default 100)
  -d    Output only valid domain names (e.g. strip IPs, wildcard domains and gibberish)
  -p string
        TLS ports to use, if not specified explicitly in host address. Use comma-separated list (default "443")
  -t int
        TLS Connection timeout in seconds (default 4)
  -v    Be verbose: Output results as 'addr -- [result list]', output errors to stderr as 'addr -- error message'
  ```
