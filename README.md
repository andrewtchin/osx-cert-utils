# osx-cert-utils
Tools to manage OS X SystemRootCertificates keychain

### Generate a list of certificates to remove

Write Ansible vars file

```
python cert_finder.py --whitelist-apple --outfile main.yml --ansible-vars --backup-outfile backup_certs
```
