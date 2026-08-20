/*
 * Comprehensive test file for System.Security.Cryptography ML-KEM (MLKem, MLKemCng,
 * MLKemOpenSsl) detection rules.
 *
 * ML-KEM (FIPS 203) is documented for the net-10.0/net-11.0 monikers — still an evolving
 * preview API (see the [Experimental("SYSLIB5006")] attribute on some overloads in the
 * official reference). See DotNetMLKem.java's class javadoc for the full, verified
 * explanation of what is/isn't modeled here and why.
 */

using System.Security.Cryptography;

public class DotNetMLKemTest
{
    // -------------------------------------------------------------------------
    // Section 1: Algorithm-parameterized creation (parameter set captured from the
    // MLKemAlgorithm argument)
    // -------------------------------------------------------------------------

    public void TestGenerateKey512()
    {
        var kem = MLKem.GenerateKey(MLKemAlgorithm.MLKem512);
    }

    public void TestGenerateKey768()
    {
        var kem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
    }

    public void TestGenerateKey1024()
    {
        var kem = MLKem.GenerateKey(MLKemAlgorithm.MLKem1024);
    }

    public void TestImportDecapsulationKey()
    {
        byte[] decapsulationKeyBytes = new byte[64];
        var kem = MLKem.ImportDecapsulationKey(MLKemAlgorithm.MLKem768, decapsulationKeyBytes);
    }

    public void TestImportEncapsulationKey()
    {
        byte[] encapsulationKeyBytes = new byte[64];
        var kem = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, encapsulationKeyBytes);
    }

    public void TestImportPrivateSeed()
    {
        byte[] seedBytes = new byte[64];
        var kem = MLKem.ImportPrivateSeed(MLKemAlgorithm.MLKem512, seedBytes);
    }

    // -------------------------------------------------------------------------
    // Section 2: Structural imports (no MLKemAlgorithm argument — the parameter set is
    // embedded in the encoded key material / PEM text and cannot be recovered)
    // -------------------------------------------------------------------------

    public void TestImportPkcs8PrivateKey()
    {
        byte[] pkcs8Bytes = new byte[64];
        var kem = MLKem.ImportPkcs8PrivateKey(pkcs8Bytes);
    }

    public void TestImportSubjectPublicKeyInfo()
    {
        byte[] spkiBytes = new byte[64];
        var kem = MLKem.ImportSubjectPublicKeyInfo(spkiBytes);
    }

    public void TestImportFromPem()
    {
        string pem = "-----BEGIN PRIVATE KEY-----";
        var kem = MLKem.ImportFromPem(pem);
    }

    public void TestImportEncryptedPkcs8PrivateKey()
    {
        byte[] passwordBytes = new byte[16];
        byte[] encryptedBytes = new byte[64];
        var kem = MLKem.ImportEncryptedPkcs8PrivateKey(passwordBytes, encryptedBytes);
    }

    public void TestImportFromEncryptedPem()
    {
        string pem = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
        string password = "hunter2";
        var kem = MLKem.ImportFromEncryptedPem(pem, password);
    }

    // -------------------------------------------------------------------------
    // Section 3: Native-interop constructors (no MLKemAlgorithm argument — wrap an
    // already-existing native key handle)
    // -------------------------------------------------------------------------

    public void TestMLKemCng()
    {
        CngKey cngKey = null;
        var kem = new MLKemCng(cngKey);
    }

    public void TestMLKemOpenSsl()
    {
        SafeEvpPKeyHandle handle = null;
        var kem = new MLKemOpenSsl(handle);
    }

    // -------------------------------------------------------------------------
    // Section 4: Encapsulate / Decapsulate operations
    // -------------------------------------------------------------------------

    public void TestEncapsulate()
    {
        var kem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        byte[] ciphertext;
        byte[] sharedSecret;
        kem.Encapsulate(out ciphertext, out sharedSecret);
    }

    public void TestDecapsulate()
    {
        var kem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        byte[] ciphertext = new byte[1088];
        byte[] sharedSecret = kem.Decapsulate(ciphertext);
    }

    // -------------------------------------------------------------------------
    // Section 5: Combined usage pattern (generation + encapsulate + decapsulate)
    // -------------------------------------------------------------------------

    public void TestFullFlow()
    {
        var kem = MLKem.GenerateKey(MLKemAlgorithm.MLKem1024);
        byte[] ciphertext;
        byte[] sharedSecret;
        kem.Encapsulate(out ciphertext, out sharedSecret);
        byte[] decapsulated = kem.Decapsulate(ciphertext);
    }
}
