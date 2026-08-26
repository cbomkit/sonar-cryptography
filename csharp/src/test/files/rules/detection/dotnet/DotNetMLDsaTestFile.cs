/*
 * Comprehensive test file for System.Security.Cryptography ML-DSA (MLDsa, MLDsaCng,
 * MLDsaOpenSsl) and Composite ML-DSA (CompositeMLDsa, CompositeMLDsaCng) detection rules.
 *
 * ML-DSA (FIPS 204) is documented for the net-10.0/net-11.0 monikers, with no [Experimental]
 * attribute on the plain MLDsa/MLDsaCng/MLDsaOpenSsl surface. Composite ML-DSA additionally
 * carries [Experimental("SYSLIB5006")] at the class level (still a preview API). See
 * DotNetMLDsa.java's class javadoc for the full, verified explanation of what is/isn't modeled
 * here and why (in particular the Composite ML-DSA modeling compromise).
 */

using System.Security.Cryptography;

public class DotNetMLDsaTest
{
    // -------------------------------------------------------------------------
    // Section 1: MLDsa algorithm-parameterized creation (parameter set captured from the
    // MLDsaAlgorithm argument)
    // -------------------------------------------------------------------------

    public void TestGenerateKey44()
    {
        var dsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa44);
    }

    public void TestGenerateKey65()
    {
        var dsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
    }

    public void TestGenerateKey87()
    {
        var dsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa87);
    }

    public void TestImportMLDsaPrivateKey()
    {
        byte[] privateKeyBytes = new byte[64];
        var dsa = MLDsa.ImportMLDsaPrivateKey(MLDsaAlgorithm.MLDsa65, privateKeyBytes);
    }

    public void TestImportMLDsaPrivateSeed()
    {
        byte[] seedBytes = new byte[32];
        var dsa = MLDsa.ImportMLDsaPrivateSeed(MLDsaAlgorithm.MLDsa44, seedBytes);
    }

    public void TestImportMLDsaPublicKey()
    {
        byte[] publicKeyBytes = new byte[64];
        var dsa = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa87, publicKeyBytes);
    }

    // -------------------------------------------------------------------------
    // Section 2: MLDsa structural imports (no MLDsaAlgorithm argument — the parameter set is
    // embedded in the encoded key material / PEM text and cannot be recovered)
    // -------------------------------------------------------------------------

    public void TestImportPkcs8PrivateKey()
    {
        byte[] pkcs8Bytes = new byte[64];
        var dsa = MLDsa.ImportPkcs8PrivateKey(pkcs8Bytes);
    }

    public void TestImportSubjectPublicKeyInfo()
    {
        byte[] spkiBytes = new byte[64];
        var dsa = MLDsa.ImportSubjectPublicKeyInfo(spkiBytes);
    }

    public void TestImportFromPem()
    {
        string pem = "-----BEGIN PRIVATE KEY-----";
        var dsa = MLDsa.ImportFromPem(pem);
    }

    public void TestImportEncryptedPkcs8PrivateKey()
    {
        byte[] passwordBytes = new byte[16];
        byte[] encryptedBytes = new byte[64];
        var dsa = MLDsa.ImportEncryptedPkcs8PrivateKey(passwordBytes, encryptedBytes);
    }

    public void TestImportFromEncryptedPem()
    {
        string pem = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
        string password = "hunter2";
        var dsa = MLDsa.ImportFromEncryptedPem(pem, password);
    }

    // -------------------------------------------------------------------------
    // Section 3: MLDsa native-interop constructors (no MLDsaAlgorithm argument — wrap an
    // already-existing native key handle)
    // -------------------------------------------------------------------------

    public void TestMLDsaCng()
    {
        CngKey cngKey = null;
        var dsa = new MLDsaCng(cngKey);
    }

    public void TestMLDsaOpenSsl()
    {
        SafeEvpPKeyHandle handle = null;
        var dsa = new MLDsaOpenSsl(handle);
    }

    // -------------------------------------------------------------------------
    // Section 4: MLDsa Sign / Verify operations
    // -------------------------------------------------------------------------

    public void TestSignData()
    {
        var dsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        byte[] data = new byte[32];
        byte[] context = new byte[0];
        byte[] signature = dsa.SignData(data, context);
    }

    public void TestVerifyData()
    {
        var dsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        byte[] data = new byte[32];
        byte[] signature = new byte[3309];
        byte[] context = new byte[0];
        bool ok = dsa.VerifyData(data, signature, context);
    }

    public void TestSignMu()
    {
        var dsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        byte[] mu = new byte[64];
        byte[] signature = dsa.SignMu(mu);
    }

    public void TestVerifyMu()
    {
        var dsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        byte[] mu = new byte[64];
        byte[] signature = new byte[3309];
        bool ok = dsa.VerifyMu(mu, signature);
    }

    public void TestSignPreHash()
    {
        var dsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        byte[] hash = new byte[64];
        string hashOid = "2.16.840.1.101.3.4.2.3";
        byte[] context = new byte[0];
        byte[] signature = dsa.SignPreHash(hash, hashOid, context);
    }

    public void TestVerifyPreHash()
    {
        var dsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        byte[] hash = new byte[64];
        byte[] signature = new byte[3309];
        string hashOid = "2.16.840.1.101.3.4.2.3";
        byte[] context = new byte[0];
        bool ok = dsa.VerifyPreHash(hash, signature, hashOid, context);
    }

    // -------------------------------------------------------------------------
    // Section 5: CompositeMLDsa algorithm-parameterized creation (parameter set captured
    // verbatim from the CompositeMLDsaAlgorithm argument, e.g. "MLDsa44WithECDsaP256")
    // -------------------------------------------------------------------------

    public void TestCompositeGenerateKey()
    {
        var dsa = CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256);
    }

    public void TestCompositeImportPrivateKey()
    {
        byte[] privateKeyBytes = new byte[64];
        var dsa = CompositeMLDsa.ImportCompositeMLDsaPrivateKey(
            CompositeMLDsaAlgorithm.MLDsa65WithRSA3072Pss, privateKeyBytes);
    }

    public void TestCompositeImportPublicKey()
    {
        byte[] publicKeyBytes = new byte[64];
        var dsa = CompositeMLDsa.ImportCompositeMLDsaPublicKey(
            CompositeMLDsaAlgorithm.MLDsa87WithEd448, publicKeyBytes);
    }

    // -------------------------------------------------------------------------
    // Section 6: CompositeMLDsa structural imports (no CompositeMLDsaAlgorithm argument)
    // -------------------------------------------------------------------------

    public void TestCompositeImportPkcs8PrivateKey()
    {
        byte[] pkcs8Bytes = new byte[64];
        var dsa = CompositeMLDsa.ImportPkcs8PrivateKey(pkcs8Bytes);
    }

    public void TestCompositeImportSubjectPublicKeyInfo()
    {
        byte[] spkiBytes = new byte[64];
        var dsa = CompositeMLDsa.ImportSubjectPublicKeyInfo(spkiBytes);
    }

    public void TestCompositeImportFromPem()
    {
        string pem = "-----BEGIN PRIVATE KEY-----";
        var dsa = CompositeMLDsa.ImportFromPem(pem);
    }

    public void TestCompositeImportEncryptedPkcs8PrivateKey()
    {
        byte[] passwordBytes = new byte[16];
        byte[] encryptedBytes = new byte[64];
        var dsa = CompositeMLDsa.ImportEncryptedPkcs8PrivateKey(passwordBytes, encryptedBytes);
    }

    public void TestCompositeImportFromEncryptedPem()
    {
        string pem = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
        string password = "hunter2";
        var dsa = CompositeMLDsa.ImportFromEncryptedPem(pem, password);
    }

    // -------------------------------------------------------------------------
    // Section 7: CompositeMLDsaCng native-interop constructor
    // -------------------------------------------------------------------------

    public void TestCompositeMLDsaCng()
    {
        CngKey cngKey = null;
        var dsa = new CompositeMLDsaCng(cngKey);
    }

    // -------------------------------------------------------------------------
    // Section 8: CompositeMLDsa Sign / Verify operations
    // -------------------------------------------------------------------------

    public void TestCompositeSignData()
    {
        var dsa = CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256);
        byte[] data = new byte[32];
        byte[] context = new byte[0];
        byte[] signature = dsa.SignData(data, context);
    }

    public void TestCompositeVerifyData()
    {
        var dsa = CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256);
        byte[] data = new byte[32];
        byte[] signature = new byte[2400];
        byte[] context = new byte[0];
        bool ok = dsa.VerifyData(data, signature, context);
    }

    // -------------------------------------------------------------------------
    // Section 9: Combined usage pattern (generation + sign + verify)
    // -------------------------------------------------------------------------

    public void TestFullFlow()
    {
        var dsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa87);
        byte[] data = new byte[32];
        byte[] context = new byte[0];
        byte[] signature = dsa.SignData(data, context);
        bool ok = dsa.VerifyData(data, signature, context);
    }
}
