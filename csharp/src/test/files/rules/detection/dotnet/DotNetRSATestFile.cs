/*
 * Comprehensive test file for System.Security.Cryptography RSA detection rules.
 *
 * Covers all four RSA-related classes and their complete operational API surface:
 *   - RSA (abstract base)
 *   - RSACng, RSACryptoServiceProvider, RSAOpenSsl (derived from RSA)
 *
 * Architecture note: all methods inherited from RSA / AsymmetricAlgorithm (KeySize,
 * Encrypt, Decrypt, SignData, VerifyData, SignHash, VerifyHash, Try* variants, etc.)
 * are covered once here. The detection engine tracks the variable and fires the same
 * depending rules for every concrete RSA subclass.
 */

using System.Security.Cryptography;

public class DotNetRSATest
{
    // -------------------------------------------------------------------------
    // Section 1: Factory methods / constructors
    // -------------------------------------------------------------------------

    public void TestRsaCreate()
    {
        var rsa = RSA.Create(); // Noncompliant
    }

    public void TestRsaCreateWithKeySize()
    {
        var rsa = RSA.Create(2048);
    }

    public void TestRsaCsp()
    {
        var rsa = new RSACryptoServiceProvider();
    }

    public void TestRsaCng()
    {
        var rsa = new RSACng();
    }

    public void TestRsaOpenSsl()
    {
        var rsa = new RSAOpenSsl();
    }

    // -------------------------------------------------------------------------
    // Section 2: Property setters (via assignment → synthetic set_X invocations)
    // -------------------------------------------------------------------------

    public void TestPropertyKeySize2048()
    {
        var rsa = RSA.Create();
        rsa.KeySize = 2048;
    }

    public void TestPropertyKeySize4096()
    {
        var rsa = RSA.Create();
        rsa.KeySize = 4096;
    }

    // -------------------------------------------------------------------------
    // Section 3: Encrypt / Decrypt
    // -------------------------------------------------------------------------

    public void TestEncrypt()
    {
        var rsa = RSA.Create();
        byte[] data = new byte[32];
        byte[] ciphertext = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
    }

    public void TestDecrypt()
    {
        var rsa = RSA.Create();
        byte[] ciphertext = new byte[256];
        byte[] plaintext = rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
    }

    public void TestTryEncrypt()
    {
        var rsa = RSA.Create();
        byte[] data = new byte[32];
        byte[] destination = new byte[256];
        int bytesWritten;
        rsa.TryEncrypt(data, destination, RSAEncryptionPadding.Pkcs1, out bytesWritten);
    }

    public void TestTryDecrypt()
    {
        var rsa = RSA.Create();
        byte[] ciphertext = new byte[256];
        byte[] destination = new byte[32];
        int bytesWritten;
        rsa.TryDecrypt(ciphertext, destination, RSAEncryptionPadding.Pkcs1, out bytesWritten);
    }

    // -------------------------------------------------------------------------
    // Section 4: SignData / TrySignData / VerifyData
    // -------------------------------------------------------------------------

    public void TestSignData()
    {
        var rsa = RSA.Create();
        byte[] data = new byte[64];
        byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    public void TestTrySignData()
    {
        var rsa = RSA.Create();
        byte[] data = new byte[64];
        byte[] destination = new byte[256];
        int bytesWritten;
        rsa.TrySignData(data, destination, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, out bytesWritten);
    }

    public void TestVerifyData()
    {
        var rsa = RSA.Create();
        byte[] data = new byte[64];
        byte[] signature = new byte[256];
        bool valid = rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    // -------------------------------------------------------------------------
    // Section 5: SignHash / TrySignHash / VerifyHash
    // -------------------------------------------------------------------------

    public void TestSignHash()
    {
        var rsa = RSA.Create();
        byte[] hash = new byte[32];
        byte[] signature = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    public void TestTrySignHash()
    {
        var rsa = RSA.Create();
        byte[] hash = new byte[32];
        byte[] destination = new byte[256];
        int bytesWritten;
        rsa.TrySignHash(hash, destination, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, out bytesWritten);
    }

    public void TestVerifyHash()
    {
        var rsa = RSA.Create();
        byte[] hash = new byte[32];
        byte[] signature = new byte[256];
        bool valid = rsa.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    // -------------------------------------------------------------------------
    // Section 6: Combined usage patterns (real-world scenarios)
    // Demonstrates that depending rules fire correctly for ALL derived classes.
    // -------------------------------------------------------------------------

    public void TestRsaCngFullFlow()
    {
        var rsa = new RSACng();
        rsa.KeySize = 3072;
        byte[] data = new byte[32];
        byte[] ciphertext = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
    }

    public void TestRsaCspSignFlow()
    {
        var rsa = new RSACryptoServiceProvider();
        byte[] data = new byte[64];
        byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    public void TestRsaOpenSslVerifyFlow()
    {
        var rsa = new RSAOpenSsl();
        byte[] data = new byte[64];
        byte[] signature = new byte[256];
        bool valid = rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
}
