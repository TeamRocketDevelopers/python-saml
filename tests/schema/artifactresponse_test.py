import unittest
from lxml import etree
from saml import schema
from saml.schema import saml, samlp
from datetime import datetime, timedelta
"""UNFINISHED"""

class ArtifactResponseTest(unittest.TestCase):
    def setUp(self):
        self.p = samlp.ArtifactResponse()
        self.p.issuer = saml.Issuer("saml://concordus")
        self.p.in_response_to = "saml://crm"
        self.p.status = samlp.Status()
        self.p.status.code = samlp.StatusCode()
        self.p.status.code.value = samlp.StatusCode.Value.SUCCESS
        self.p.status.message = "Success; yes, that is all."
        self.p.message = samlp.LogoutRequest()

        self.x = samlp.ArtifactResponse.serialize(self.p)
        self.s = etree.tostring(self.x, pretty_print=True)


    def runTest(self):
        #print self.a

        print(self.s)
        self.e = etree.XML(self.s)
        self.c = samlp.ArtifactResponse.deserialize(self.e)
        print('--------------------------')
        self.x2 = samlp.ArtifactResponse.serialize(self.c)
        self.s2 = etree.tostring(self.x2, pretty_print=True)

        print(self.s2)
        self.s2 = etree.tostring(self.x2, pretty_print=True)
        self.assertEquals(self.s, self.s2, "XML doesn't match")

