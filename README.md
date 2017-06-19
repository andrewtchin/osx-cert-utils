# osx-cert-utils
Tools to manage OS X SystemRootCertificates keychain


## Overview

Use `cert_finder.py` to generate a list of root CAs to remove from system's trusted roots. You
can use a predefined whitelist to determine which certificates to remove or generate your own
whitelist using [go-tls-scraper](https://github.com/andrewtchin/go-tls-scraper). 
Your list of certificates to remove can then be used with
[ansible-osx-remove-root-ca](https://github.com/andrewtchin/ansible-osx-remove-root-ca). 


## Generate a list of certificates to remove

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

Whitelist Apple roots
```
python osx_cert_utils/cert_finder.py --whitelist-apple --outfile apple
```

This command generates:
```
apple-20170618.yml         # Ansible vars file
apple-all-20170618.bak     # Backup of all system roots
apple-remove-20170618.bak  # Backup of roots that will be removed
```


## Generate your own whitelist

You can generate whitelist of certificates to remove by providing a list of domains to whitelist to [go-tls-scraper](https://github.com/andrewtchin/go-tls-scraper) which will determine the root certificate used by each site. 


## Restore backup

TODO


## Remove the root certificates

To use remove functions, SIP must be disabled.
Restart, Command + r, `csrutil disable`.
Reboot and `csrutil enable` after removing certificates.

Add the `--remove` flag to perform the removal
```
python osx_cert_utils/cert_finder.py --whitelist-apple --remove --outfile apple
```

### Ansible

Certificates can also be removed using Ansible with the generated Ansible vars file.

TODO
