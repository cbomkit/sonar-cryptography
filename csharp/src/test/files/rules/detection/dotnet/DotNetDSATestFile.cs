/*
 * Comprehensive test file for the System.Security.Cryptography DSA detection rules.
 *
 * Covers DSA and its three implementations (DSACng, DSACryptoServiceProvider, DSAOpenSsl), the
 * full signing and verification surface, the key size in each of its argument positions, and the
 * cases whose values cannot be resolved and must stay absent.
 */

using System.Security.Cryptography;

public class DotNetDSATest
{
    private const int ConfiguredDsaKeySize = 3072;

    // --- creation, no arguments ---------------------------------------------------------------

    public void TestDsaCreate()
    {
        var dsa = DSA.Create();
    }

    public void TestDsaCng()
    {
        var dsa = new DSACng();
    }

    public void TestDsaCryptoServiceProvider()
    {
        var dsa = new DSACryptoServiceProvider();
    }

    public void TestDsaOpenSsl()
    {
        var dsa = new DSAOpenSsl();
    }

    // --- creation with a key size --------------------------------------------------------------

    public void TestDsaCreateWithKeySize()
    {
        var dsa = DSA.Create(2048);
    }

    public void TestDsaCngWithKeySize()
    {
        var dsa = new DSACng(3072);
    }

    public void TestDsaCspWithKeySizeAndParameters()
    {
        var dsa = new DSACryptoServiceProvider(1024, null);
    }

    public void TestDsaOpenSslWithKeySize()
    {
        var dsa = new DSAOpenSsl(2048);
    }

    public void TestDsaCreateFromConstant()
    {
        var dsa = DSA.Create(ConfiguredDsaKeySize);
    }

    // DSAParameters is not a key size: none may be reported.
    public void TestDsaCreateFromParameters()
    {
        DSAParameters parameters = default;
        var dsa = DSA.Create(parameters);
    }

    // --- property setter -----------------------------------------------------------------------

    public void TestDsaPropertyKeySize()
    {
        var dsa = DSA.Create();
        dsa.KeySize = 1024;
    }

    // --- signing and verification over data, which names a hash --------------------------------

    public void TestDsaSignData()
    {
        var dsa = DSA.Create();
        byte[] data = new byte[64];
        byte[] signature = dsa.SignData(data, HashAlgorithmName.SHA256);
    }

    // SignData(data, offset, count, hashAlgorithm): the hash sits at index three.
    public void TestDsaSignDataWithOffset()
    {
        var dsa = DSA.Create();
        byte[] data = new byte[64];
        byte[] signature = dsa.SignData(data, 0, 32, HashAlgorithmName.SHA256);
    }

    public void TestDsaTrySignData()
    {
        var dsa = DSA.Create();
        byte[] data = new byte[64];
        byte[] destination = new byte[64];
        int bytesWritten;
        dsa.TrySignData(data, destination, HashAlgorithmName.SHA384, out bytesWritten);
    }

    public void TestDsaVerifyData()
    {
        var dsa = DSA.Create();
        byte[] data = new byte[64];
        byte[] signature = new byte[40];
        bool valid = dsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
    }

    // VerifyData(data, offset, count, signature, hashAlgorithm)
    public void TestDsaVerifyDataWithOffset()
    {
        var dsa = DSA.Create();
        byte[] data = new byte[64];
        byte[] signature = new byte[40];
        bool valid = dsa.VerifyData(data, 0, 32, signature, HashAlgorithmName.SHA384);
    }

    // The hash written as a keyword argument.
    public void TestDsaSignDataNamedHash()
    {
        var dsa = DSA.Create();
        byte[] data = new byte[64];
        byte[] signature = dsa.SignData(data, hashAlgorithm: HashAlgorithmName.SHA384);
    }

    // --- signing over an already-computed hash -------------------------------------------------

    // CreateSignature and VerifySignature take a raw hash and name no algorithm.
    public void TestDsaCreateSignature()
    {
        var dsa = DSA.Create();
        byte[] hash = new byte[20];
        byte[] signature = dsa.CreateSignature(hash);
    }

    public void TestDsaVerifySignature()
    {
        var dsa = DSA.Create();
        byte[] hash = new byte[20];
        byte[] signature = new byte[40];
        bool valid = dsa.VerifySignature(hash, signature);
    }

    // DSACryptoServiceProvider.SignHash(rgbHash, str) names the hash as a string.
    public void TestDsaCspSignHash()
    {
        var dsa = new DSACryptoServiceProvider();
        byte[] hash = new byte[20];
        byte[] signature = dsa.SignHash(hash, "SHA1");
    }

    public void TestDsaCspVerifyHash()
    {
        var dsa = new DSACryptoServiceProvider();
        byte[] hash = new byte[20];
        byte[] signature = new byte[40];
        bool valid = dsa.VerifyHash(hash, "SHA1", signature);
    }

    // --- unresolvable values -------------------------------------------------------------------

    // The hash arrives as a method parameter whose callers disagree.
    public void TestDsaSignDataUnknownHash(HashAlgorithmName algorithm)
    {
        var dsa = DSA.Create();
        byte[] data = new byte[64];
        byte[] signature = dsa.SignData(data, algorithm);
    }

    public void CallDsaUnknownSha1()
    {
        TestDsaSignDataUnknownHash(HashAlgorithmName.SHA1);
    }

    public void CallDsaUnknownSha256()
    {
        TestDsaSignDataUnknownHash(HashAlgorithmName.SHA256);
    }
}
