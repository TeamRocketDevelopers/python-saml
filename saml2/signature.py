# -*- coding: utf-8 -*-

"""
Sign and verify signatures using the `python-xmlsec` library.

.. autofunction:: sign
.. autofunction:: verify
"""
from saml2.schema import constants as co


def sign(xml, key_file, cert_file=None, password=None,
         sign_algorithm=co.SIGN_CRYPT.rsa_sha1,
         digest_algorithm=co.SIGN_CRYPT.sha1):
    """
    Sign an XML document with the given private key file. This will add a
    <Signature> element to the document.

    :param lxml.etree._Element xml: The document to sign
    :param file key_file: The x509 private key to sign the document with
    :param file cert_file: The x509 cert to sign the document with
    :param str password: The password used to access the private key
    :param const sign_algorithm: The sign algorithm to use.
    :param const digest_algorithm: The digest algorithm to use.

    :rtype: None

    Example usage:
    ::
        from saml2 import schema
        from lxml import etree

        document = schema.AuthenticationRequest()
        xml_document = document.serialize()
        with open('my_key_file.pem', 'r+') as stream:
            sign(xml_document, stream)

        print etree.tostring(xml_document)

    Produces the following XML document:

    .. code-block:: xml

        <samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            Version="2.0" ID="_6087de0b111b44349a70ff40191a4c0c"
            IssueInstant="2015-03-16T21:06:39Z">
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
                <SignedInfo>
                    <CanonicalizationMethod
                        Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                        <SignatureMethod
                            Algorithm="http://www.w3.org/2000/
                            09/xmldsig#rsa-sha1"/>
                            <Reference>
                                <Transforms>
                                    <Transform
                                        Algorithm="http://www.w3.org/2000/
                                        09/xmldsig#enveloped-signature"/>
                                </Transforms>
                                <DigestMethod
                                    Algorithm="http://www.w3.org/2000/
                                    09/xmldsig#sha1"/>
                                    <DigestValue>
                                        94O1FOjRE4JQYVDqStkYzne9StQ=
                                    </DigestValue>
                            </Reference>
                </SignedInfo>
                <SignatureValue>
                    aFYRRjtB3bDyLLJzLZmsn0K4SXmOpFYJ+8R8D31VojgiF37FOElbE56UFbm8BAjn
                    l2AixrUGXP4djxoxxnfBD/reYw5yVuIVXlMxKec784nF2V4GyrfwJOKaNmlVPkq5
                    c8SI+EkKJ02mwiail0Zvjb9FzwvlYD+osMSXvJXVqnGHQDVFlhwbBRRVB6t44/M3
                    TzC4mLSVhuvcpsm4GTQSpGkHP7HvweKN/OTc0aTy8Kh/YUrImwnUCii+J0EW4nGg
                    71eZyq/IiSPnTD09WDHsWe3g29kpicZXqrQCWeLE2zfVKtyxxs7PyEmodH19jXyz
                    wh9hQ8t6PFO47Ros5aV0bw==
                </SignatureValue>
            </Signature>
        </samlp:AuthnRequest>
    """

    # Import xmlsec here to delay initializing the C library in
    # case we don't need it.
    import xmlsec

    # Set sign algorithm to use
    sign_map = {
        co.SIGN_CRYPT.dsa_sha1: xmlsec.Transform.DSA_SHA1,
        co.SIGN_CRYPT.rsa_sha1: xmlsec.Transform.RSA_SHA1,
        co.SIGN_CRYPT.rsa_sha256: xmlsec.Transform.RSA_SHA256,
        co.SIGN_CRYPT.rsa_sha384: xmlsec.Transform.RSA_SHA384,
        co.SIGN_CRYPT.rsa_sha512: xmlsec.Transform.RSA_SHA512,
    }
    sign_algorithm_transform = sign_map.get(
        sign_algorithm, co.SIGN_CRYPT.rsa_sha1)

    # Resolve the SAML/2.0 element in question.
    from saml2.schema.base import _element_registry
    element = _element_registry.get(xml.tag)

    # Create a signature template for RSA-SHA1 enveloped signature.
    signature_node = xmlsec.template.create(
        xml,
        xmlsec.Transform.EXCL_C14N,
        sign_algorithm_transform,
        ns='ds')

    # Add the <ds:Signature/> node to the document.
    xml.insert(element.meta.signature_index, signature_node)

    # Add the <ds:Reference/> node to the signature template.
    digest_map = {
        co.SIGN_CRYPT.sha1: xmlsec.Transform.SHA1,
        co.SIGN_CRYPT.sha256: xmlsec.Transform.SHA256,
        co.SIGN_CRYPT.sha384: xmlsec.Transform.SHA384,
        co.SIGN_CRYPT.sha512: xmlsec.Transform.SHA512,
    }
    digest_algorithm_transform = digest_map.get(
        digest_algorithm, co.SIGN_CRYPT.sha1)

    ref = xmlsec.template.add_reference(
        signature_node, digest_algorithm_transform)

    # Add the enveloped transform descriptor.
    xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)
    xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)
    key_info = xmlsec.template.ensure_key_info(signature_node)
    xmlsec.template.add_x509_data(key_info)

    # Create a digital signature context (no key manager is needed).
    ctx = xmlsec.SignatureContext()

    # Load private key.
    key = xmlsec.Key.from_memory(key_file, xmlsec.KeyFormat.PEM, password)

    # Load the public cert if given.
    if cert_file:
        key.load_cert_from_memory(cert_file, xmlsec.KeyFormat.PEM)

    # Set the key on the context.
    ctx.key = key

    # Sign the template.
    ctx.sign(signature_node)


def verify(xml, stream):
    """
    Verify the signaure of an XML document with the given certificate.
    Returns `True` if the document is signed with a valid signature.
    Returns `False` if the document is not signed or if the signature is
    invalid.

    :param lxml.etree._Element xml: The document to sign
    :param file stream: The private key to sign the document with

    :rtype: Boolean
    """
    # Import xmlsec here to delay initializing the C library in
    # case we don't need it.
    import xmlsec

    # Find the <Signature/> node.
    signature_node = xmlsec.tree.find_node(xml, xmlsec.Node.SIGNATURE)
    if signature_node is None:
        # No `signature` node found; we cannot verify
        return False

    # Create a digital signature context (no key manager is needed).
    ctx = xmlsec.SignatureContext()

    # Register <Response/> and <Assertion/>
    ctx.register_id(xml)
    for assertion in xml.xpath("//*[local-name()='Assertion']"):
        ctx.register_id(assertion)

    # Load the public key.
    key = None
    for fmt in [
            xmlsec.KeyFormat.PEM,
            xmlsec.KeyFormat.CERT_PEM]:
        stream.seek(0)
        try:
            key = xmlsec.Key.from_memory(stream, fmt)
            break
        except ValueError:
            # xmlsec now throws when it can't load the key
            pass

    # Set the key on the context.
    ctx.key = key

    # Verify the signature.
    try:
        ctx.verify(signature_node)

        return True

    except Exception:
        return False
