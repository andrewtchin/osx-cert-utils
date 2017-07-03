"""
Maps of cert SHA-1 fingerprint and cert name.
"""

# http://netsekure.org/2010/05/results-after-30-days-of-almost-no-trusted-cas/
# Skipped Entrust.net Secure Server Certification Authority (Legacy)
NETSEKURE_MINIMAL_CERTS = {
    '7E784A101C8265CC2DE1F16D47B440CAD90A1945': 'Equifax Secure Global eBusiness CA-1',
    '85371CA6E550143DCE2803471BDE3A09E8F8770F': 'Class 3 Public Primary Certification Authority - G2',
    '742C3192E607E424EB4549542BE1BBC53E6174E2': 'Class 3 Public Primary Certification Authority',
    'D23209AD23D314232174E40D7F9D62139786633A': 'Equifax Secure Certificate Authority',
    '97817950D81C9670CC34D809CF794431367EF474': 'GTE CyberTrust Global Root',
    '02FAF3E291435468607857694DF5E45B68851868': 'AddTrust External CA Root',
    '627F8D7827656399D27D7F9044C9FEB3F33EFA9A': 'Thawte Premium Server CA',
    '2796BAE63F1801E277261BA0D77770028F20EEE4': 'Go Daddy Class 2 Certification Authority',
    'B1BC968BD4F49D622AA89A81F2150152A41D829C': 'GlobalSign Root CA',
}

# http://blog.ivanristic.com/downloads/Qualys_SSL_Labs-State_of_SSL_2010-v1.6.pdf
# Skipped StartCom Certification Authority - website doesn't have root cert info
QUALYS_MINIMAL_CERTS = {
    '2796BAE63F1801E277261BA0D77770028F20EEE4': 'Go Daddy Class 2 Certification Authority',
    'D23209AD23D314232174E40D7F9D62139786633A': 'Equifax Secure Certificate Authority',
    '0483ED3399AC3608058722EDBC5E4600E3BEF9D7': 'UTN-USERFirst-Hardware',
    '627F8D7827656399D27D7F9044C9FEB3F33EFA9A': 'Thawte Premium Server CA',
    'E0AB059420725493056062023670F7CD2EFC6666': 'Thawte Premium Server CA',
    '9FAD91A6CE6AC6C50047C44EC9D4A50D92D84979': 'Thawte Server CA',
    '23E594945195F2414803B4D564D2A3A3F5D88B8C': 'Thawte Server CA',
    'A1DB6393916F17E4185509400415C70240B0AE6B': 'Class 3 Public Primary Certification Authority',  # VeriSign
    '85371CA6E550143DCE2803471BDE3A09E8F8770F': 'Class 3 Public Primary Certification Authority - G2',  # Verisign Trust Network
    'B1BC968BD4F49D622AA89A81F2150152A41D829C': 'GlobalSign Root CA',
    '74F8A3C3EFE7B390064B83903C21646020E5DFCE': 'Network Solutions Certificate Authority',
    'AD7E1C28B064EF8F6003402014C3D0E3370EB58A': 'Starfield Class 2 Certification Authority',
    '7E784A101C8265CC2DE1F16D47B440CAD90A1945': 'Equifax Secure Global eBusiness CA-1',
    '6631BF9EF74F9EB6C9D5A60CBA6ABED1F7BDEF7B': 'COMODO Certification Authority',
    '8782C6C304353BCFD29692D2593E7D44D934FF11': 'SecureTrust CA',
    '4EB6D578499B1CCF5F581EAD56BE3D9B6744A5E5': 'VeriSign Class 3 Public Primary Certification Authority - G5',
    '5FB7EE0633E259DBAD0C4C9AE6D38F1A61C7DC25': 'DigiCert High Assurance EV Root CA',
    '503006091D97D4F5AE39F7CBE7927D7D652D3431': 'Entrust.net Certification Authority (2048)',
    'B31EB1B740E36C8402DADC37D44DF5D4674952F9': 'Entrust Root Certification Authority',
    '97817950D81C9670CC34D809CF794431367EF474': 'GTE CyberTrust Global Root',
}

APPLE_CERTS = {
    '14698989BFB2950921A42452646D37B50AF017E2': 'Apple Root CA - G2',
    '580F804792ABC63BBB80154D4DFDDD8B2EF2674E': 'Apple Root Certificate Authority',
    'B52CB02FD567E0359FE8FA4D4C41037970FE01B0': 'Apple Root CA - G3',
    '611E5B662C593A08FF58D14AE22452D198DF6C60': 'Apple Root CA',
}
