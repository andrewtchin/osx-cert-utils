"""
Find certificates in SystemRootCertificates keychain in OS X to remove.
"""

import argparse
import datetime

import OpenSSL

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

    def whitelist_netsekure(self):
        """Whitelist major certificates from Netsekure survey."""
        self.update_whitelist(cert_constants.NETSEKURE_MINIMAL_CERTS)

    def whitelist_qualys(self):
        """Whitelist major certificates from Qualys survey."""
        self.update_whitelist(cert_constants.QUALYS_MINIMAL_CERTS)

    def whitelist_apple(self):
        """Whitelist Apple certificates."""
        self.update_whitelist(cert_constants.APPLE_CERTS)

    def whitelist_top_10000(self):
        """Whitelist top 10000 Alexa 1M certificates from Untrusted Roots survey."""
        self.update_whitelist(cert_constants.UNTRUSTED_ROOTS_SURVEY_10000)

    def whitelist_top_100000(self):
        """Whitelist top 100000 Alexa 1M certificates from Untrusted Roots survey."""
        self.update_whitelist(cert_constants.UNTRUSTED_ROOTS_SURVEY_100000)

    def whitelist_top_1M(self):
        """Whitelist all Alexa 1M certificates from Untrusted Roots survey."""
        self.update_whitelist(cert_constants.UNTRUSTED_ROOTS_SURVEY_1M)

    def whitelist_file(self, whitelist_file):
        """Whitelist fingerprints in whitelist_file."""
        # TODO
        vals = dict()
        self.update_whitelist(vals)

    def generate_remove_list(self):
        """Generate the removal list."""
        certs = osx_cert_utils.get_all_certs_map()
        print('Found {} certs'.format(len(certs)))

        cr = OpenSSL.crypto
        for sha in certs:
            c = cr.load_certificate(cr.FILETYPE_PEM, certs[sha])
            s = c.get_subject().get_components()
            print('{}'.format(s))

            if sha not in self.whitelist:
                print('Adding cert to remove: {} {}'.format(sha, s))
                self.remove_certs[sha] = certs[sha]
            else:
                print('Skipping whitelisted cert: {} {}'.format(sha, s))

    def generate_ansible_vars(self, outfile):
        """Generate the removal file in Ansible vars format.

        Args:
            outfile: path to write output file
        """
        cr = OpenSSL.crypto
        with open(outfile, 'w') as fp:
            fp.write('certs:\n')
            for sha in self.remove_certs:
                c = cr.load_certificate(cr.FILETYPE_PEM, self.remove_certs[sha])
                s = c.get_subject().get_components()
                st = ''.join(['    - ', sha, '  # ', repr(s), '\n'])
                fp.write(st)

        print('Generated list of {} certs: {}\n'.format(len(self.remove_certs), outfile))

    def generate_backup(self, cert_map, outfile):
        """Generate the backup file.

        Contains PEMs of certificates that will be removed.

        Args:
            cert_map: map of sha1:pem cert
            outfile: path to write output file
        """
        backup_certs = 0
        error_certs = 0
        with open(outfile, 'w') as fp:
            for sha in cert_map:
                print("Backing up {}".format(sha))
                fp.write(sha)
                fp.write('\n')
                fp.write(cert_map[sha])
                backup_certs = backup_certs + 1

        print('\nBacked up {} certs.'.format(backup_certs))
        print('Failed to backup {} certs.'.format(error_certs))


def parse_args():
    parser = argparse.ArgumentParser(description='Generate a list of certificates hashes.')
    parser.add_argument('--whitelist-netsekure',
                        action='store_true',
                        help='whitelist major CAs identified by Netsekure.')
    parser.add_argument('--whitelist-qualys',
                        action='store_true',
                        help='whitelist major CAs identified by Qualys.')
    parser.add_argument('--whitelist-apple',
                        action='store_true',
                        help='whitelist Apple root CAs.')
    parser.add_argument('--whitelist-top-10000',
                        action='store_true',
                        help='whitelist CAs for top 10000 of Alexa 1M.')
    parser.add_argument('--whitelist-top-100000',
                        action='store_true',
                        help='whitelist CAs for top 100000 of Alexa 1M.')
    parser.add_argument('--whitelist-top-1M',
                        action='store_true',
                        help='whitelist CAs for Alexa 1M.')
    parser.add_argument('--whitelist-file',
                        help='whitelist file')
    parser.add_argument('--remove',
                        action='store_true',
                        help='remove the CAs in the remove list from the root store.')
    parser.add_argument('--outfile',
                        required=True,
                        help='output basename for removal list and backup')
    return parser.parse_args()


def main():
    """Generate a list of certificate hashes, defaults to include all certificates.

    Use whitelist options to prevent removal of certain lists.
    Blacklist options will override certificate list generated by whitelist options.
    """
    args = parse_args()
    ts = datetime.datetime.now().strftime('%Y%m%d')

    certs = CertOps()

    if args.whitelist_netcraft:
        certs.whitelist_netcraft()
    if args.whitelist_netsekure:
        certs.whitelist_netsekure()
    if args.whitelist_qualys:
        certs.whitelist_qualys()
    if args.whitelist_apple:
        certs.whitelist_apple()
    if args.whitelist_top_10000:
        certs.whitelist_top_10000()
    if args.whitelist_top_100000:
        certs.whitelist_top_100000()
    if args.whitelist_top_1M:
        certs.whitelist_top_1M()
    if args.whitelist_file:
        certs.whitelist_file(args.whitelist_file)

    # backup all certs
    o = '-'.join([args.outfile, 'all', ts]) + '.bak'
    certs.generate_backup(osx_cert_utils.get_all_certs_map(), o)
    print('Backup all certs complete')

    certs.generate_remove_list()

    # backup remove certs
    o = '-'.join([args.outfile, 'remove', ts]) + '.bak'
    certs.generate_backup(certs.remove_certs, o)
    print('Backup remove certs complete')

    # output hashes in format for Ansible vars file
    o = '-'.join([args.outfile, ts]) + '.yml'
    certs.generate_ansible_vars(o)

    # remove the certificates
    if args.remove:
        print('Remove selected certificates')
        for c in certs.remove_certs:
            osx_cert_utils.remove_cert(c)
            print('Removed {}'.format(c))


if __name__ == '__main__':
    main()
