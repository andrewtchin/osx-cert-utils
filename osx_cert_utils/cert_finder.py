"""
Find certificates in SystemRootCertificates keychain in OS X to remove.
"""

import argparse
import pprint
import subprocess

import cert_map
import osx_cert_utils


class CertFinder(object):
    def __init__(self):
        self.remove_certs = dict()
        self.whitelist = dict()

    def update_whitelist(self, certs):
        """Add certificates to the whitelist.
        Args:
            certs: dict of SHA-1 and name to add
        """
        self.whitelist.update(certs)

    def whitelist_netcraft(self):
        """Whitelist major certificates from Netcraft SSL survey."""
        self.update_whitelist(cert_map.NETCRAFT_SURVEY_CERTS)

    def whitelist_netsekure(self):
        """Whitelist major certificates from Netsekure survey."""
        self.update_whitelist(cert_map.NETSEKURE_MINIMAL_CERTS)

    def whitelist_qualys(self):
        """Whitelist major certificates from Qualys survey."""
        self.update_whitelist(cert_map.QUALYS_MINIMAL_CERTS)

    def whitelist_apple(self):
        """Whitelist Apple certificates."""
        self.update_whitelist(cert_map.APPLE_CERTS)

    def generate_remove_list(self):
        """Generate the removal list.
        """
        all_certs = osx_cert_utils.get_all_certs()
        certs = osx_cert_utils.get_cert_name_map(all_certs)

        for cert in certs:
            if cert not in self.whitelist:
                self.remove_certs[cert] = certs[cert]

    def generate_output(self, outfile, ansible_vars):
        """Generate the removal file.
        Outputs dict or Ansible vars format.
        Args:
            outfile: path to write output file
            ansible_vars: boolean to output as Ansible vars format
        """
        if ansible_vars:
            with open(outfile, 'w') as fp:
                fp.write('certs:\n')
                for cert in self.remove_certs:
                    str = ''.join(['    - ', cert, '  # ', self.remove_certs[cert], '\n'])
                    fp.write(str)
        else:
            with open(outfile, 'w') as fp:
                pprint.pprint(self.remove_certs, fp)

        print('Generated list of {} certs.\n'.format(len(self.remove_certs)))

    def generate_backup(self, outfile):
        """Generate the backup file.
        Contains PEMs of certificates that will be removed.
        Args:
            outfile: path to write output file
        """
        backup_certs = 0
        error_certs = 0
        with open(outfile, 'w') as fp:
            for cert in self.remove_certs:
                try:
                    cert = osx_cert_utils.get_cert(self.remove_certs[cert], True)
                    fp.write(cert)
                    backup_certs = backup_certs + 1
                except subprocess.CalledProcessError as e:
                    if e.returncode == 44:
                        print('Failed to backup {} {}'.format(cert,
                                                              self.remove_certs[cert]))
                        error_certs = error_certs + 1
                    else:
                        raise

        print('\nBacked up {} certs.'.format(backup_certs))
        print('Failed to backup {} certs.'.format(error_certs))


def parse_args():
    parser = argparse.ArgumentParser(description='Generate a list of certificates hashes.')
    parser.add_argument('--whitelist-netcraft',
                        action='store_true',
                        help='whitelist major CAs identified by Netcraft SSL survey.')
    parser.add_argument('--whitelist-netsekure',
                        action='store_true',
                        help='whitelist major CAs identified by Netsekure.')
    parser.add_argument('--whitelist-qualys',
                        action='store_true',
                        help='whitelist major CAs identified by Qualys.')
    parser.add_argument('--whitelist-apple',
                        action='store_true',
                        help='whitelist Apple root CAs.')
    parser.add_argument('--ansible-vars',
                        action='store_true',
                        help='output hashes in format for Ansible vars file')
    parser.add_argument('--outfile',
                        required=True,
                        help='output filename')
    parser.add_argument('--backup-outfile',
                        help='output filename for backup of PEMs removed')
    return parser.parse_args()


def main():
    """Generate a list of certificate hashes.
    Defaults to include all certificates.
    Use whitelist options to prevent removal of certain lists.
    Blacklist options will be override certificate list generated by whitelist options.
    """
    args = parse_args()

    cert_finder = CertFinder()

    if args.whitelist_netcraft:
        cert_finder.whitelist_netcraft()
    if args.whitelist_netsekure:
        cert_finder.whitelist_netsekure()
    if args.whitelist_qualys:
        cert_finder.whitelist_qualys()
    if args.whitelist_apple:
        cert_finder.whitelist_apple()

    cert_finder.generate_remove_list()
    cert_finder.generate_output(args.outfile, args.ansible_vars)
    if args.backup_outfile:
        cert_finder.generate_backup(args.backup_outfile)


if __name__ == '__main__':
    main()
