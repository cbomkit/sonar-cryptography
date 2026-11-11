using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

public class DotNetCertificateRequestTest {

    // --- RSA overloads: hash and padding ------------------------------------------------------

    public void TestRsaPkcs1(RSA rsa) {
        var req = new CertificateRequest("CN=test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); // Noncompliant
    }

    public void TestRsaPssWithDistinguishedName(RSA rsa) {
        var req = new CertificateRequest( // Noncompliant
            new X500DistinguishedName("CN=test"), rsa, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
    }

    // --- ECDsa and PublicKey overloads: no padding --------------------------------------------

    public void TestEcdsa(ECDsa ecdsa) {
        var req = new CertificateRequest("CN=test", ecdsa, HashAlgorithmName.SHA256); // Noncompliant
    }

    public void TestPublicKey(X500DistinguishedName name, PublicKey publicKey) {
        var req = new CertificateRequest(name, publicKey, HashAlgorithmName.SHA512); // Noncompliant
    }

    // --- a weak hash is reported as written ---------------------------------------------------

    public void TestWeakHash(RSA rsa) {
        var req = new CertificateRequest("CN=test", rsa, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1); // Noncompliant
    }

    // --- keyword arguments out of declared order ----------------------------------------------

    public void TestNamedReordered(RSA rsa) {
        var req = new CertificateRequest( // Noncompliant
            subjectName: "CN=test",
            padding: RSASignaturePadding.Pss,
            hashAlgorithm: HashAlgorithmName.SHA256,
            key: rsa);
    }

    // --- the hash is only known to the caller -------------------------------------------------

    public void TestHashNotKnown(RSA rsa, HashAlgorithmName hash) {
        var req = new CertificateRequest("CN=test", rsa, hash, RSASignaturePadding.Pkcs1); // Noncompliant
    }

    // --- the key is created inside the call ---------------------------------------------------

    public void TestInlineKey() {
        var req = new CertificateRequest( // Noncompliant
            "CN=test", RSA.Create(3072), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); // Noncompliant
    }

    // --- X509SignatureGenerator ---------------------------------------------------------------

    public void TestGeneratorRsa(RSA rsa) {
        var generator = X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pss); // Noncompliant
    }

    public void TestGeneratorEcdsa(ECDsa ecdsa) {
        var generator = X509SignatureGenerator.CreateForECDsa(ecdsa); // Noncompliant
    }
}
