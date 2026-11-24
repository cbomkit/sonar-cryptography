using System;
using System.Security.Cryptography.Xml;

public class DotNetXmlTest {

    // --- Reference.DigestMethod: the digest of a signed reference ---------------------------

    public void TestDigestConstant(Reference reference) {
        reference.DigestMethod = SignedXml.XmlDsigSHA256Url; // Noncompliant
    }

    public void TestDigestLiteral(Reference reference) {
        reference.DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha512"; // Noncompliant
    }

    public void TestDigestWeak(Reference reference) {
        reference.DigestMethod = SignedXml.XmlDsigSHA1Url; // Noncompliant
    }

    public Reference TestDigestInInitializer() {
        var reference = new Reference { Uri = "", DigestMethod = SignedXml.XmlDsigSHA384Url }; // Noncompliant
        return reference;
    }

    // --- SignedInfo.SignatureMethod: the signature algorithm --------------------------------

    public void TestSignatureRsa(SignedInfo signedInfo) {
        signedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url; // Noncompliant
    }

    public void TestSignatureEcdsa(SignedInfo signedInfo) {
        signedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"; // Noncompliant
    }

    public void TestSignatureHmac(SignedInfo signedInfo) {
        signedInfo.SignatureMethod = SignedXml.XmlDsigHMACSHA1Url; // Noncompliant
    }

    // --- EncryptionMethod: the cipher of encrypted data or key transport --------------------

    public EncryptionMethod TestEncryptionAes() {
        return new EncryptionMethod(EncryptedXml.XmlEncAES256Url); // Noncompliant
    }

    public EncryptionMethod TestEncryptionRsaOaep() {
        return new EncryptionMethod("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"); // Noncompliant
    }

    public void TestKeyAlgorithm(EncryptionMethod method) {
        method.KeyAlgorithm = EncryptedXml.XmlEncTripleDESUrl; // Noncompliant
    }

    // --- an identifier that is not an algorithm of that role: a node is not invented --------

    public void TestUnknownUri(Reference reference) {
        reference.DigestMethod = "urn:example:not-an-algorithm";
    }

    // --- only the caller knows the value: no finding at all ------------------------------------

    public void TestValueNotKnown(Reference reference, string uri) {
        reference.DigestMethod = uri;
    }

    // --- the usual form: a property of a property --------------------------------------------

    public void TestChainedSetter(SignedXml signedXml) {
        signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url; // Noncompliant
    }
}
