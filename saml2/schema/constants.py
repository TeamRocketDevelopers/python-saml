from collections import namedtuple


# Sign & Crypto
SIGN_CRYPT = (namedtuple('SignAndCrypt', [
    'sha1', 'sha256', 'sha384', 'sha512',
    'dsa_sha1', 'rsa_sha1', 'rsa_sha256', 'rsa_sha384', 'rsa_sha512',
]))(
    sha1='http://www.w3.org/2000/09/xmldsig#sha1',
    sha256='http://www.w3.org/2001/04/xmlenc#sha256',
    sha384='http://www.w3.org/2001/04/xmldsig-more#sha384',
    sha512='http://www.w3.org/2001/04/xmlenc#sha512',

    dsa_sha1='http://www.w3.org/2000/09/xmldsig#dsa-sha1',
    rsa_sha1='http://www.w3.org/2000/09/xmldsig#rsa-sha1',
    rsa_sha256='http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    rsa_sha384='http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
    rsa_sha512='http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
)
