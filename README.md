# osx-cert-utils
Tools to manage OS X SystemRootCertificates keychain

## Overview

Use `cert_finder.py` to generate a list of root CAs to remove from system's trusted roots. You
can use a predefined whitelist to determine which certificates to remove or generate your own
whitelist using (go-tls-scraper)[https://github.com/andrewtchin/go-tls-scraper]. 
Your list of certificates to remove can then be used with
(ansible-osx-remove-root-ca)[https://github.com/andrewtchin/ansible-osx-remove-root-ca]. 

### Generate a list of certificates to remove

Use predefined whitelists:

* Netcraft survey
* Netsekure
* Qualys
* Apple
* Alexa top 1M
* Alexa top 100k

See available whitelists:
```
python osx_cert_utils/cert_finder.py --help
```

Write Ansible vars file with your selections:
```
python cert_finder.py --whitelist-apple --outfile main.yml --ansible-vars --backup-outfile removed-certs
```

#### Generate your own whitelist

You can generate whitelist of certificates to remove by providing a list of domains to whitelist to (go-tls-scraper)[https://github.com/andrewtchin/go-tls-scraper] which will determine the root certificate used by each site. 


### Generate backup of all certificates

```
python cert_finder.py --backup-outfile removed-certs
```

### Restore backup


