/*
 * Comprehensive test file for System.Security.Cryptography SLH-DSA (SlhDsa, SlhDsaCng,
 * SlhDsaOpenSsl) detection rules.
 *
 * SLH-DSA (FIPS 205, formerly SPHINCS+) is documented for the net-10.0/net-11.0 monikers, with
 * the whole SlhDsa surface (base class, both derived classes, and SlhDsaAlgorithm) carrying a
 * class-level [Experimental("SYSLIB5006")] attribute (still a preview API, unlike the now-stable
 * plain ML-DSA/ML-KEM surface). See DotNetSlhDsa.java's class javadoc for the full, verified
 * explanation of what is/isn't modeled here and why, and how it differs from ML-DSA (no
 * ImportSlhDsaPrivateSeed, no SignMu/VerifyMu, no Composite variant, different parameter set
 * names).
 */

using System.Security.Cryptography;

public class DotNetSlhDsaTest
{
    // -------------------------------------------------------------------------
    // Section 1: SlhDsa algorithm-parameterized creation (parameter set captured from the
    // SlhDsaAlgorithm argument)
    // -------------------------------------------------------------------------

    public void TestGenerateKeySha2_128s()
    {
        var dsa = SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_128s);
    }

    public void TestGenerateKeyShake256f()
    {
        var dsa = SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaShake256f);
    }

    public void TestImportSlhDsaPrivateKey()
    {
        byte[] privateKeyBytes = new byte[64];
        var dsa = SlhDsa.ImportSlhDsaPrivateKey(SlhDsaAlgorithm.SlhDsaSha2_192f, privateKeyBytes);
    }

    public void TestImportSlhDsaPublicKey()
    {
        byte[] publicKeyBytes = new byte[32];
        var dsa = SlhDsa.ImportSlhDsaPublicKey(SlhDsaAlgorithm.SlhDsaShake128s, publicKeyBytes);
    }

    // -------------------------------------------------------------------------
    // Section 2: SlhDsa structural imports (no SlhDsaAlgorithm argument — the parameter set is
    // embedded in the encoded key material / PEM text and cannot be recovered)
    // -------------------------------------------------------------------------

    public void TestImportPkcs8PrivateKey()
    {
        byte[] pkcs8Bytes = new byte[64];
        var dsa = SlhDsa.ImportPkcs8PrivateKey(pkcs8Bytes);
    }

    public void TestImportSubjectPublicKeyInfo()
    {
        byte[] spkiBytes = new byte[64];
        var dsa = SlhDsa.ImportSubjectPublicKeyInfo(spkiBytes);
    }

    public void TestImportFromPem()
    {
        string pem = "-----BEGIN PRIVATE KEY-----";
        var dsa = SlhDsa.ImportFromPem(pem);
    }

    public void TestImportEncryptedPkcs8PrivateKey()
    {
        byte[] passwordBytes = new byte[16];
        byte[] encryptedBytes = new byte[64];
        var dsa = SlhDsa.ImportEncryptedPkcs8PrivateKey(passwordBytes, encryptedBytes);
    }

    public void TestImportFromEncryptedPem()
    {
        string pem = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
        string password = "hunter2";
        var dsa = SlhDsa.ImportFromEncryptedPem(pem, password);
    }

    // -------------------------------------------------------------------------
    // Section 3: SlhDsa native-interop constructors (no SlhDsaAlgorithm argument — wrap an
    // already-existing native key handle)
    // -------------------------------------------------------------------------

    public void TestSlhDsaCng()
    {
        CngKey cngKey = null;
        var dsa = new SlhDsaCng(cngKey);
    }

    public void TestSlhDsaOpenSsl()
    {
        SafeEvpPKeyHandle handle = null;
        var dsa = new SlhDsaOpenSsl(handle);
    }

    // -------------------------------------------------------------------------
    // Section 4: SlhDsa Sign / Verify operations (no SignMu/VerifyMu — confirmed absent from
    // the official SlhDsa reference)
    // -------------------------------------------------------------------------

    public void TestSignData()
    {
        var dsa = SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_128s);
        byte[] data = new byte[32];
        byte[] context = new byte[0];
        byte[] signature = dsa.SignData(data, context);
    }

    public void TestVerifyData()
    {
        var dsa = SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_128s);
        byte[] data = new byte[32];
        byte[] signature = new byte[7856];
        byte[] context = new byte[0];
        bool ok = dsa.VerifyData(data, signature, context);
    }

    public void TestSignPreHash()
    {
        var dsa = SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_128s);
        byte[] hash = new byte[32];
        string hashOid = "2.16.840.1.101.3.4.2.1";
        byte[] context = new byte[0];
        byte[] signature = dsa.SignPreHash(hash, hashOid, context);
    }

    public void TestVerifyPreHash()
    {
        var dsa = SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_128s);
        byte[] hash = new byte[32];
        byte[] signature = new byte[7856];
        string hashOid = "2.16.840.1.101.3.4.2.1";
        byte[] context = new byte[0];
        bool ok = dsa.VerifyPreHash(hash, signature, hashOid, context);
    }

    // -------------------------------------------------------------------------
    // Section 5: combined usage pattern (generation + sign + verify)
    // -------------------------------------------------------------------------

    public void TestFullFlow()
    {
        var dsa = SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaShake256f);
        byte[] data = new byte[32];
        byte[] context = new byte[0];
        byte[] signature = dsa.SignData(data, context);
        bool ok = dsa.VerifyData(data, signature, context);
    }
}
