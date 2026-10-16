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

    // -------------------------------------------------------------------------
    // Section 7: single-argument constructor overloads that carry a key size
    // (added with DotNetKeySizeOrAlgorithmFactory / arity-split creation rules)
    // -------------------------------------------------------------------------

    public void TestRsaCryptoServiceProviderWithKeySize()
    {
        var rsa = new RSACryptoServiceProvider(3072);
    }

    public void TestRsaCngWithKeySize()
    {
        var rsa = new RSACng(4096);
    }

    public void TestRsaOpenSslWithKeySize()
    {
        var rsa = new RSAOpenSsl(2048);
    }

    // Real-world pattern verified against the Bitwarden server corpus
    // (util/Seeder/Data/Generators/SshKeyDataGenerator.cs): a `using`-scoped variable created
    // inside a `for` loop, with the key size as a literal argument. Exercises both the arity-split
    // RSA.Create(int) capture and block flattening (the `for` body is not its own scope).
    public void TestRsaCreateInsideForLoop()
    {
        for (var i = 0; i < 3; i++)
        {
            using var rsa = RSA.Create(2048);
        }
    }

    // -------------------------------------------------------------------------
    // Section 8: parameter forms — offsets, keywords, PSS, OAEP digests, and
    // values that must stay unresolved
    // -------------------------------------------------------------------------

    private const int ConfiguredKeySize = 3072;

    // SignData(data, offset, count, hashAlgorithm, padding): the hash and padding sit at
    // indices three and four here.
    public void TestSignDataWithOffset()
    {
        var rsa = RSA.Create();
        byte[] data = new byte[64];
        byte[] signature = rsa.SignData(data, 0, 32, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
    }

    // VerifyData(data, offset, count, signature, hashAlgorithm, padding) — the six-parameter form.
    public void TestVerifyDataWithOffset()
    {
        var rsa = RSA.Create();
        byte[] data = new byte[64];
        byte[] signature = new byte[256];
        bool valid = rsa.VerifyData(data, 0, 32, signature, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
    }

    // Hash and padding written as keyword arguments, in the reverse of the declared order.
    public void TestSignDataNamedReordered()
    {
        var rsa = RSA.Create();
        byte[] data = new byte[64];
        byte[] signature = rsa.SignData(data, padding: RSASignaturePadding.Pss, hashAlgorithm: HashAlgorithmName.SHA512);
    }

    // OAEP with a SHA-512 digest rather than the SHA-256 used above.
    public void TestEncryptOaepSha512()
    {
        var rsa = RSA.Create();
        byte[] data = new byte[32];
        byte[] ciphertext = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA512);
    }

    // Key size from a const field.
    public void TestRsaCreateFromConstant()
    {
        var rsa = RSA.Create(ConfiguredKeySize);
    }

    // RSAParameters is not a key size: none may be reported.
    public void TestRsaCreateFromParameters()
    {
        RSAParameters parameters = default;
        var rsa = RSA.Create(parameters);
    }

    // The padding arrives from a call this engine cannot see into: the encryption must still be
    // reported, the padding must not.
    public void TestEncryptUnknownPadding()
    {
        var rsa = RSA.Create();
        byte[] data = new byte[32];
        var padding = ResolvePaddingFromConfiguration();
        byte[] ciphertext = rsa.Encrypt(data, padding);
    }

    private RSAEncryptionPadding ResolvePaddingFromConfiguration()
    {
        return RSAEncryptionPadding.CreateOaep(HashAlgorithmName.SHA256);
    }

    // The hash arrives as a method parameter whose callers disagree, while the padding is a
    // literal: the padding must be reported and the digest must not.
    public void TestSignDataUnknownHash(HashAlgorithmName algorithm)
    {
        var rsa = RSA.Create();
        byte[] data = new byte[64];
        byte[] signature = rsa.SignData(data, algorithm, RSASignaturePadding.Pkcs1);
    }

    public void CallRsaSignUnknownHashSha256()
    {
        TestSignDataUnknownHash(HashAlgorithmName.SHA256);
    }

    public void CallRsaSignUnknownHashSha384()
    {
        TestSignDataUnknownHash(HashAlgorithmName.SHA384);
    }
}
