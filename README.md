# cero
Cero will connect to remote hosts, and read domain names from the certificates they provided during TLS handshake. <br>
It is not limited to only HTTPS, since cero can grab certificates from any protocol over TLS (SMTPS, FTPS, etc.), just give it the right ports to connect to.

## Installation / Update
```bash
go get -u github.com/glebarez/cero
```

## Usage
Connect to remote host using its domain name and default port (443)
```bash
cero yahoo.com
```
With above command line, cero will output following domain names by reading TLS certificate, provided by the remote host
```
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
Cero is fast and concurrent, so you are free to provide it with list of target addresses. The concurrency level can be set with -c flag:
```bash
cat myTargets.txt | cero -c 1000
```

Cero will accept bare IP as input:
```bash
cero 10.0.0.1
```

Or even entire CIDR range!
```bash
cero 10.0.0.1/22
```

By default, cero uses port 443 for initiating TLS connection, but you can use specific port for every target
```bash
cero use-specific-port.com:10443 use-default-port.com
```

And you can redefine default port with -p option:
```bash
cat myTargets.txt | cero -p 8443
```

Port specification is even supported on CIDR ranges:
```bash
cero 192.1.1.1/16:8443
```

## Output control
By default, cero will only output successfully scraped domain names as simple list (to standard output), and the errors (if any)  will be suppressed<br>
If you want see what errors were encountered, or what names came from what addresses, use the -v flag. This will format output a little differently, and also write error messages to standard error.
```bash
cero -v example.com example.com:80
example.com:80 -- tls: first record does not look like a TLS handshake
example.com:443 -- [www.example.org example.com example.edu example.net example.org www.example.com www.example.edu www.example.net]
```
For precise controls, use shell redirects:
```
cero -v example.com example.com:80 2>/dev/null
example.com:443 -- [www.example.org example.com example.edu example.net example.org www.example.com www.example.edu www.example.net]
```

## Full option list
```bash
Usage of cero:
  -c int
        Concurrency level (default 100)
  -p int
        Default TLS port to use, if not specified explicitly in host address (default 443)
  -t int
        TLS Connection timeout in seconds (default 4)
  -v    Be verbose: Output results as 'addr -- [result list]', output errors to stderr as 'addr -- error message'
  ```