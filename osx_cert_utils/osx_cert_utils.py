"""
Utilities to manage the SystemRootCertificates keychain in OS X.
"""

import shlex
import StringIO
import subprocess

import OpenSSL


def get_all_certs_map():
    """Map SHA-1 of each certificate to the PEM format x509 certificate"""
    cert_map = dict()
    sha = None
    cert = ''

    all_certs_cmd = shlex.split('security find-certificate -a -p -Z /System/Library/Keychains/SystemRootCertificates.keychain')
    certs = subprocess.check_output(all_certs_cmd)

    s = StringIO.StringIO(certs)
    for line in s:
        if line.startswith('SHA-1 hash:'):
            sha = line.split()[-1]
        else:
            cert = cert + line
            if '-----END CERTIFICATE-----' in line:
                cert_map[sha] = cert
                sha = None
                cert = ''

    return cert_map


def get_cert(name, certs=None):
    """Get certificate by name search in OU or CN

    find-certificate -c only searches by CN but there are a few system roots without CN

    Args:
        name: certificate name to search for
        certs: certificate map, calls `get_all_certs_map` if None
    """
    if not certs:
        certs = get_all_certs_map()

    cr = OpenSSL.crypto
    for sha, cert in certs:
        c = cr.load_certificate(cr.FILETYPE_PEM, cert)
        s = c.get_subject().get_components()
        for p in s:
            if name in p[1]:
                return cert


def pem_to_der(infile_path, outfile_path):
    """Convert PEM format to DER format.

    Args:
        infile_path: path to input PEM file
        outfile_path: path to output DER file
    """
    convert_cmd = shlex.split('openssl x509 -in {} -out {} -inform PEM -outform DER'.format(infile_path, outfile_path))
    subprocess.check_call(convert_cmd)


def add_cert(cert_path):
    """Add a certificate to the SystemRootCertificates keychain.

    Input must be in DER format.
    Requires root privileges.

    Args:
        cert_path: path to input der file
    """
    add_cmd = shlex.split('security add-certificates -k /System/Library/Keychains/SystemRootCertificates.keychain {}'.format(cert_path))
    subprocess.check_call(add_cmd)


def remove_cert(sha1):
    """Remove a certificate with matching SHA1

    Args:
        sha1: SHA1 hash of the certificate to remove
    """
    rm_cmd = shlex.split('security delete-certificate -Z {} /System/Library/Keychains/SystemRootCertificates.keychain'.format(sha1))
    subprocess.check_call(rm_cmd)
