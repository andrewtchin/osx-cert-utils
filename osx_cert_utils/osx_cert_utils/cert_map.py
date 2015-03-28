#!/usr/bin/env python

"""
Maps of cert SHA-1 fingerprint and cert name.
"""

# http://www.netcraft.com/internet-data-mining/ssl-survey/
NETCRAFT_SURVEY_CERTS = {
    '26A16C235A2472229B23628025BC8097C88524A1': 'Symantec Class 3 Public Primary Certification Authority - G6',
    '40B331A0E9BFE855BC3993CA704F4EC251D41D8F': 'Symantec Class 2 Public Primary Certification Authority - G6',
    '517F611E29916B5382FB72E744D98DC3CC536D64': 'Symantec Class 1 Public Primary Certification Authority - G6',
    '58D52DB93301A4FD291A8C9645A08FEE7F529282': 'Symantec Class 3 Public Primary Certification Authority - G4',
    '6724902E4801B02296401046B4B1672CA975FD2B': 'Symantec Class 2 Public Primary Certification Authority - G4',
    '84F2E3DD83133EA91D19527F02D729BFC15FE667': 'Symantec Class 1 Public Primary Certification Authority - G4',
    '039EEDB80BE7A03C6953893B20D2D9323A4C2AFD': 'GeoTrust Primary Certification Authority - G3',
    '323C118E1BF7B8B65254E2E2100DD6029037F096': 'GeoTrust Primary Certification Authority',
    '8D1784D537F3037DEC70FE578B519A99E610D7B0': 'GeoTrust Primary Certification Authority - G2',
    'DE28F4A4FFE5B92FA3C503D1A349A7F9962A8212': 'GeoTrust Global CA',
    '209900B63D955728140CD13622D8C687A4EB0085': 'Thawte Personal Freemail CA',
    '20CEB1F0F51C0E19A9F38DB1AA8E038CAA7AC701': 'Thawte Timestamping CA',
    '23E594945195F2414803B4D564D2A3A3F5D88B8C': 'Thawte Server CA',
    '42F818E833063BF516C6618C1E60FD0F35C47621': 'Thawte Personal Basic CA',
    '627F8D7827656399D27D7F9044C9FEB3F33EFA9A': 'Thawte Premium Server CA',
    '91C6D6EE3E8AC86384E548C299295C756C817B81': 'thawte Primary Root CA',
    '9FAD91A6CE6AC6C50047C44EC9D4A50D92D84979': 'Thawte Server CA',
    'AADBBC22238FC401A127BB38DDF41DDB089EF012': 'thawte Primary Root CA - G2',  # 2016-03-27 Not currently used https://www.thawte.com/roots/
    'CA39D8EA4822137F338DCA79566EDDF0547ECEA7': 'Thawte Personal Premium CA',
    'E0AB059420725493056062023670F7CD2EFC6666': 'Thawte Premium Server CA',
    'E61883AE84CAC1C1CD52ADE8E9252B45A64FB7E2': 'Thawte Personal Freemail CA',
    'F18B538D1BE903B6A6F056435B171589CAF36BF2': 'thawte Primary Root CA - G3',
    '132D0D45534B6997CDB2D5C339E25576609B5CC6': 'VeriSign Class 3 Public Primary Certification Authority - G3',
    '204285DCF7EB764195578E136BD4B7D1E98E46A5': 'VeriSign Class 1 Public Primary Certification Authority - G3',
    '22D5D8DF8F0231D18DF79DB7CF8A2D64C93F6C3A': 'VeriSign Class 3 Public Primary Certification Authority - G4',  # 2015-03-27 Not currently used https://www.symantec.com/page.jsp?id=roots
    '3679CA35668772304D30A5FB873B0FA77BB70D54': 'VeriSign Universal Root Certification Authority',  # 2015-03-27 Not currently used https://www.symantec.com/page.jsp?id=roots
    '4EB6D578499B1CCF5F581EAD56BE3D9B6744A5E5': 'VeriSign Class 3 Public Primary Certification Authority - G5',
    '61EF43D77FCAD46151BC98E0C35912AF9FEB6311': 'VeriSign Class 2 Public Primary Certification Authority - G3',
    'C8EC8C879269CB4BAB39E98D7E5767F31495739D': 'VeriSign Class 4 Public Primary Certification Authority - G3',  # 2015-03-27 Not currently used https://www.symantec.com/page.jsp?id=roots
    'A1DB6393916F17E4185509400415C70240B0AE6B': 'Class 3 Public Primary Certification Authority',  # VeriSign
    '85371CA6E550143DCE2803471BDE3A09E8F8770F': 'Class 3 Public Primary Certification Authority - G2',  # Verisign Trust Network
    '2796BAE63F1801E277261BA0D77770028F20EEE4': 'Go Daddy Class 2 Certification Authority',
    '47BEABC922EAE80E78783462A79F45C254FDE68B': 'Go Daddy Root Certificate Authority - G2',
    '925A8F8D2C6D04E0665F596AFF22D863E8256F3F': 'Starfield Services Root Certificate Authority - G2',
    'AD7E1C28B064EF8F6003402014C3D0E3370EB58A': 'Starfield Class 2 Certification Authority',
    'B51C067CEE2B0C3DF855AB2D92F4FE39D4E70F0E': 'Starfield Root Certificate Authority - G2',
    '6631BF9EF74F9EB6C9D5A60CBA6ABED1F7BDEF7B': 'COMODO Certification Authority',
    '1F24C630CDA418EF2069FFAD4FDD5F463A1B69AA': 'GlobalSign',  #2015-03-27 ECC Not currently used https://support.globalsign.com/customer/portal/articles/1426602-globalsign-root-certificates
    '2F173F7DE99667AFA57AF80AA2D1B12FAC830338': 'GlobalSign Root CA',
    '6969562E4080F424A1E7199F14BAF3EE58AB6ABB': 'GlobalSign',  # 2015-03-27 ECC Not currently used https://support.globalsign.com/customer/portal/articles/1426602-globalsign-root-certificates
    '75E0ABB6138512271C04F85FDDDE38E4B7242EFE': 'GlobalSign',
    'B1BC968BD4F49D622AA89A81F2150152A41D829C': 'GlobalSign Root CA',
    'D69B561148F01C77C54578C10926DF5B856976AD': 'GlobalSign',
    '7E04DE896A3E666D00E687D33FFAD93BE83D349E': 'DigiCert Global Root G3',
    'A14B48D943EE0A0E40904F3CE0A4C09193515D3F': 'DigiCert Assured ID Root G2',
    'A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436': 'DigiCert Global Root CA',
    'DDFB16CD4931C973A2037D3FC83A4D7D775D05E4': 'DigiCert Trusted Root G4',
    'DF3C24F9BFD666761B268073FE06D1CC8D4F82A4': 'DigiCert Global Root G2',
    'F517A24F9A48C6C9F8A200269FDC0F482CAB3089': 'DigiCert Assured ID Root G3',
    '0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43': 'DigiCert Assured ID Root CA',
    '5FB7EE0633E259DBAD0C4C9AE6D38F1A61C7DC25': 'DigiCert High Assurance EV Root CA',
    '31F1FD68226320EEC63B3F9DEA4A3E537C7C3917': 'StartCom Certification Authority G2',
    '3E2BF7F2031B96F38CE6C4D8A85D3E2D58476A0F': 'StartCom Certification Authority',
    'A3F1333FE242BFCFC5D14E8F394298406810D1A0': 'StartCom Certification Authority',
}

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
