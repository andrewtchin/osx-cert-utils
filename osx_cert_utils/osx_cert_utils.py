"""
Utilities to manage the SystemRootCertificates keychain in OS X.
"""

# import logging
# import re
import shlex
import StringIO
import subprocess


def get_all_certs():
    """Return all certificates in the SystemRootCertificates keychain
    with SHA-1 of each certificate.
    """
    all_certs_cmd = shlex.split('security find-certificate -a -Z /System/Library/Keychains/SystemRootCertificates.keychain')
    output = subprocess.check_output(all_certs_cmd)
    return output


def get_cert_name_map(certs):
    """Map name to SHA-1 of each certificate.
    Args:
        certs: output from get_all_certs in format from 'security find-certificate'
    """
    cert_map = dict()
    sha = None
    name = None

    s = StringIO.StringIO(certs)
    for line in s:
        if line.startswith('SHA-1 hash:'):
            sha = line.split()[-1]
        if '"labl"<blob>=' in line:
            name = line.split('=')[-1].strip('\n"')
            cert_map[sha] = name

    return cert_map


def normalize_cert_name(name):
    """Try to format name so that `security find-certificate` will like it"""
    '''
    r = re.compile(r'0x[A-Za-z0-9]+ +"')
    '''
    parts = name.split()
    # Drop tokens beginning with `0x`
    for p in parts:
        if p.startswith('0x'):
            i = parts.index(p)
            del(parts[i])

    # Remove `"` from tokens
    for p in parts:
        if '"' in p:
            i = parts.index(p)
            parts[i] = p.strip('"')

    # Remove tokens containing `\`
    for p in parts:
        if '\\' in p:
            i = parts.index(p)
            del(parts[i])
    name = ' '.join(parts)
    print('normalized name {}'.format(name))
    return name


def get_cert(name, pem=False):
    """Get the text output from 'security find-certificate' by name.
    Args:
        name: certificate name to search for
        pem: boolean output the cert as PEM format
    """
    print('find-certificate: {}'.format(name))
    name = normalize_cert_name(name)
    if pem:
        get_cert_cmd = shlex.split('security find-certificate -p -c {} /System/Library/Keychains/SystemRootCertificates.keychain'.format(name))
    else:
        get_cert_cmd = shlex.split('security find-certificate -c {} /System/Library/Keychains/SystemRootCertificates.keychain'.format(name))
    output = subprocess.check_output(get_cert_cmd)
    return output


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
