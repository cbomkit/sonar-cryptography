using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

public class DotNetPbeParametersTest {

    private const int Rounds = 600000;

    // --- the three AES members select PBES2 --------------------------------------------------

    public void TestAes256() {
        var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100000); // Noncompliant
    }

    public void TestAes128WeakHash() {
        var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes128Cbc, HashAlgorithmName.SHA1, 2000); // Noncompliant
    }

    public void TestAes192FromConstant() {
        int rounds = Rounds;
        var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes192Cbc, HashAlgorithmName.SHA384, rounds); // Noncompliant
    }

    // --- TripleDes3KeyPkcs12 is the older PKCS#12 scheme, not PBES2 --------------------------

    public void TestTripleDesPkcs12() {
        var pbe = new PbeParameters(PbeEncryptionAlgorithm.TripleDes3KeyPkcs12, HashAlgorithmName.SHA1, 2048); // Noncompliant
    }

    // --- created inside the call that uses it ------------------------------------------------

    public byte[] TestInlineInExport(RSA rsa) {
        return rsa.ExportEncryptedPkcs8PrivateKey(
            "password", new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA512, 210000)); // Noncompliant
    }

    // --- keyword arguments in a different order than declared --------------------------------

    public void TestNamedReordered() {
        var pbe = new PbeParameters( // Noncompliant
            iterationCount: 50000,
            hashAlgorithm: HashAlgorithmName.SHA256,
            encryptionAlgorithm: PbeEncryptionAlgorithm.Aes256Cbc);
    }

    // --- the iteration count is only known to the caller -------------------------------------

    public void TestIterationCountNotKnown(int rounds) {
        var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, rounds); // Noncompliant
    }

    // --- ExportPkcs12 with the Pkcs12ExportPbeParameters enum --------------------------------

    public byte[] TestExportPkcs12Pbes2(X509Certificate2 cert) {
        return cert.ExportPkcs12(Pkcs12ExportPbeParameters.Pbes2Aes256Sha256, "password"); // Noncompliant
    }

    public byte[] TestExportPkcs12TripleDes(X509Certificate2 cert) {
        return cert.ExportPkcs12(Pkcs12ExportPbeParameters.Pkcs12TripleDesSha1, "password"); // Noncompliant
    }

    // Default depends on the .NET version, so no scheme may be reported for it
    public byte[] TestExportPkcs12Default(X509Certificate2 cert) {
        return cert.ExportPkcs12(Pkcs12ExportPbeParameters.Default, "password");
    }
}
