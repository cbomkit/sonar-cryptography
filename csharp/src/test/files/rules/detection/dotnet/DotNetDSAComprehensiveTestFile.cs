/*
 * Comprehensive test file for System.Security.Cryptography DSA detection rules.
 *
 * Covers all four DSA-related classes and their complete operational API surface:
 *   - DSA (abstract base)
 *   - DSACng, DSACryptoServiceProvider, DSAOpenSsl (derived from DSA)
 *
 * Architecture note: all methods inherited from DSA / AsymmetricAlgorithm (KeySize,
 * CreateSignature, VerifySignature, SignData, VerifyData, Try* variants, etc.) are
 * covered once here. The detection engine tracks the variable and fires the same
 * depending rules for every concrete DSA subclass.
 */

using System.Security.Cryptography;

public class DotNetDSAComprehensiveTest
{
    // -------------------------------------------------------------------------
    // Section 1: Factory methods / constructors
    // -------------------------------------------------------------------------

    public void TestDsaCreate()
    {
        var dsa = DSA.Create();
    }

    public void TestDsaCreateWithKeySize()
    {
        var dsa = DSA.Create(2048);
    }

    public void TestDsaCng()
    {
        var dsa = new DSACng();
    }

    public void TestDsaCngWithKeySize()
    {
        var dsa = new DSACng(2048);
    }

    public void TestDsaCsp()
    {
        var dsa = new DSACryptoServiceProvider();
    }

    public void TestDsaOpenSsl()
    {
        var dsa = new DSAOpenSsl();
    }

    // -------------------------------------------------------------------------
    // Section 2: Property setters (via assignment → synthetic set_X invocations)
    // -------------------------------------------------------------------------

    public void TestPropertyKeySize1024()
    {
        var dsa = DSA.Create();
        dsa.KeySize = 1024;
    }

    public void TestPropertyKeySize2048()
    {
        var dsa = DSA.Create();
        dsa.KeySize = 2048;
    }

    public void TestPropertyKeySize3072()
    {
        var dsa = DSA.Create();
        dsa.KeySize = 3072;
    }

    // -------------------------------------------------------------------------
    // Section 3: CreateSignature / TryCreateSignature
    // -------------------------------------------------------------------------

    public void TestCreateSignature()
    {
        var dsa = DSA.Create();
        byte[] hash = new byte[20];
        byte[] signature = dsa.CreateSignature(hash);
    }

    public void TestCreateSignatureWithFormat()
    {
        var dsa = DSA.Create();
        byte[] hash = new byte[20];
        byte[] signature = dsa.CreateSignature(hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    public void TestTryCreateSignature()
    {
        var dsa = DSA.Create();
        byte[] hash = new byte[20];
        byte[] destination = new byte[64];
        int bytesWritten;
        dsa.TryCreateSignature(hash, destination, out bytesWritten);
    }

    // -------------------------------------------------------------------------
    // Section 4: VerifySignature
    // -------------------------------------------------------------------------

    public void TestVerifySignature()
    {
        var dsa = DSA.Create();
        byte[] hash = new byte[20];
        byte[] signature = new byte[64];
        bool valid = dsa.VerifySignature(hash, signature);
    }

    public void TestVerifySignatureWithFormat()
    {
        var dsa = DSA.Create();
        byte[] hash = new byte[20];
        byte[] signature = new byte[64];
        bool valid = dsa.VerifySignature(hash, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    // -------------------------------------------------------------------------
    // Section 5: SignData / TrySignData
    // -------------------------------------------------------------------------

    public void TestSignData()
    {
        var dsa = DSA.Create();
        byte[] data = new byte[64];
        byte[] signature = dsa.SignData(data, HashAlgorithmName.SHA256);
    }

    public void TestTrySignData()
    {
        var dsa = DSA.Create();
        byte[] data = new byte[64];
        byte[] destination = new byte[64];
        int bytesWritten;
        dsa.TrySignData(data, destination, HashAlgorithmName.SHA256, out bytesWritten);
    }

    // -------------------------------------------------------------------------
    // Section 6: VerifyData
    // -------------------------------------------------------------------------

    public void TestVerifyData()
    {
        var dsa = DSA.Create();
        byte[] data = new byte[64];
        byte[] signature = new byte[64];
        bool valid = dsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
    }

    // -------------------------------------------------------------------------
    // Section 7: SignHash / VerifyHash (legacy CSP-era methods; only real on
    // DSACryptoServiceProvider, not on the abstract DSA base class)
    // -------------------------------------------------------------------------

    public void TestSignHash()
    {
        var dsa = new DSACryptoServiceProvider();
        byte[] hash = new byte[20];
        byte[] signature = dsa.SignHash(hash, "SHA1");
    }

    public void TestVerifyHash()
    {
        var dsa = new DSACryptoServiceProvider();
        byte[] hash = new byte[20];
        byte[] signature = new byte[40];
        bool valid = dsa.VerifyHash(hash, "SHA1", signature);
    }

    // -------------------------------------------------------------------------
    // Section 8: Combined usage patterns (real-world scenarios)
    // Demonstrates that depending rules fire correctly for ALL derived classes.
    // -------------------------------------------------------------------------

    public void TestDsaCngFullFlow()
    {
        var dsa = new DSACng();
        dsa.KeySize = 2048;
        byte[] data = new byte[64];
        byte[] signature = dsa.SignData(data, HashAlgorithmName.SHA256);
    }

    public void TestDsaCspVerifyFlow()
    {
        var dsa = new DSACryptoServiceProvider();
        byte[] data = new byte[64];
        byte[] signature = new byte[64];
        bool valid = dsa.VerifyData(data, signature, HashAlgorithmName.SHA1);
    }

    public void TestDsaOpenSslSignFlow()
    {
        var dsa = new DSAOpenSsl();
        byte[] hash = new byte[20];
        byte[] signature = dsa.CreateSignature(hash);
    }
}
