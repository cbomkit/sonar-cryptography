using System.Security.Cryptography;
using System.Security.Cryptography.Xml;

public class CSharpChainedSetterTest {

    // `Options` is another object, so its KeySize is not the key size of rsa
    public void TestChainNotAttributedToVariable() {
        var rsa = RSA.Create(); // Noncompliant
        rsa.Options.KeySize = 4096;
    }

    // the single-level setter keeps attaching to the variable
    public void TestSingleLevelStillAttributed() {
        var rsa = RSA.Create(); // Noncompliant
        rsa.KeySize = 2048;
    }

    // a deeper chain is converted too
    public void TestDeepChain(SignedXml signedXml) {
        signedXml.Outer.Inner.DigestMethod = SignedXml.XmlDsigSHA256Url; // Noncompliant
    }

    // an index inside the chain: the target is not a plain a.b.c path, so no setter
    /*
     * The null-forgiving operator sits between two member accesses and says nothing about the
     * receiver, so the chain must still be read. This is how Sustainsys.Saml2 writes the only
     * XML signature method assignment it has, and nullable reference types make it ordinary.
     */
    public void TestNullForgivingInChain(SignedXml signedXml) {
        signedXml.SignedInfo!.SignatureMethod = SignedXml.XmlDsigRSASHA1Url; // Noncompliant
    }

    public void TestIndexedChain(SignedInfo info) {
        info.References[0].DigestMethod = SignedXml.XmlDsigSHA384Url;
    }
}
