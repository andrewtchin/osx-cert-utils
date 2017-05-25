"""
Find certificates in SystemRootCertificates keychain in OS X to remove.
"""

import argparse
# import logging
import pprint
import subprocess

import cert_constants
import osx_cert_utils


class CertOps(object):
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
        self.update_whitelist(cert_constants.NETCRAFT_SURVEY_CERTS)

    def whitelist_netsekure(self):
        """Whitelist major certificates from Netsekure survey."""
        self.update_whitelist(cert_constants.NETSEKURE_MINIMAL_CERTS)

    def whitelist_qualys(self):
        """Whitelist major certificates from Qualys survey."""
        self.update_whitelist(cert_constants.QUALYS_MINIMAL_CERTS)

    def whitelist_apple(self):
        """Whitelist Apple certificates."""
        self.update_whitelist(cert_constants.APPLE_CERTS)

    def whitelist_alexa(self):
        """Whitelist ALL Alexa 1M certificates."""
        self.update_whitelist(cert_constants.ALEXA_1M_CERTS)

    def generate_remove_list(self):
        """Generate the removal list.
        """
        all_certs = osx_cert_utils.get_all_certs()
        certs = osx_cert_utils.get_cert_name_map(all_certs)
        print('Found {} certs'.format(len(certs)))

        for cert in certs:
            if cert not in self.whitelist:
                print('Adding cert to remove: {}'.format(certs[cert]))
                self.remove_certs[cert] = certs[cert]
            else:
                print('Skipping whitelisted cert: {}'.format(certs[cert]))

    def generate_output(self, outfile, ansible_vars):
        """Generate the removal file.
        Outputs dict or Ansible vars format.
        Args:
            outfile: path to write output file
            ansible_vars: boolean to output as Ansible vars format
        """
        outfile = '-'.join([outfile, '.dat'])
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
        # TODO add timestamp
        outfile = '-'.join([outfile, '.bak'])
        with open(outfile, 'w') as fp:
            for cert in self.remove_certs:
                try:
                    # logging.info("Backing up %s", cert)
                    print("Backing up {}".format(cert))
                    cert = osx_cert_utils.get_cert(self.remove_certs[cert], True)
                    fp.write(cert)
                    backup_certs = backup_certs + 1
                except subprocess.CalledProcessError as e:
                    if e.returncode == 44:
                        # logging.error('Failed to backup fingerptint: %s name: %s', cert,
                        #              self.remove_certs[cert])
                        print('---------------------------------')
                        print('Failed to backup fingerptint: {} name: {}'.format(cert,
                                      self.remove_certs[cert]))
                        print('---------------------------------')
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
    parser.add_argument('--whitelist-alexa',
                        action='store_true',
                        help='whitelist CAs for all Alexa 1M.')
    parser.add_argument('--ansible-vars',
                        action='store_true',
                        help='output hashes in format for Ansible vars file')
    parser.add_argument('--outfile',
                        required=True,
                        help='output basename for removal list and backup')
    return parser.parse_args()


def main():
    """Generate a list of certificate hashes, defaults to include all certificates.

    Use whitelist options to prevent removal of certain lists.
    Blacklist options will override certificate list generated by whitelist options.
    """
    # logging.basicConfig(level=logging.DEBUG)
    args = parse_args()

    certs = CertOps()

    if args.whitelist_netcraft:
        certs.whitelist_netcraft()
    if args.whitelist_netsekure:
        certs.whitelist_netsekure()
    if args.whitelist_qualys:
        certs.whitelist_qualys()
    if args.whitelist_apple:
        certs.whitelist_apple()
    if args.whitelist_alexa:
        certs.whitelist_alexa()

    certs.generate_remove_list()
    certs.generate_output(args.outfile, args.ansible_vars)
    certs.generate_backup(args.outfile)


if __name__ == '__main__':
    main()
