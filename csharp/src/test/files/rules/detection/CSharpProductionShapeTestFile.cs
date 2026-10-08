/*
 * Shapes taken from real .NET libraries, reproduced here rather than vendored.
 *
 * Each section reproduces a construct that was found to defeat detection when the rule set was
 * run against ASP.NET Core's Data Protection stack and the Bitwarden server, and each is now
 * expected to work. The point of this file is that none of these constructs is exotic: the whole
 * file is inside a conditional compilation region, the namespace is file-scoped, the classes are
 * internal and unsafe, the buffers are stack-allocated and pinned, and the sizes are const fields.
 */

#if NETCOREAPP

using System;
using System.Security.Cryptography;

namespace Probe.Production.Shapes;

internal sealed unsafe class AesGcmEncryptorShape
{
    // A const field holding the tag size, as ASP.NET Core's AesGcmAuthenticatedEncryptor does.
    private const int TAG_SIZE_IN_BYTES = 16;
    private const int NONCE_SIZE_IN_BYTES = 12;
    private const int DERIVED_KEY_SIZE_IN_BYTES = 32;

    public void Decrypt(byte[] ciphertext)
    {
        byte[] derivedKey = new byte[DERIVED_KEY_SIZE_IN_BYTES];
        byte[] nonce = new byte[NONCE_SIZE_IN_BYTES];
        byte[] tag = new byte[TAG_SIZE_IN_BYTES];
        byte[] plaintext = new byte[ciphertext.Length];

        fixed (byte* derivedKeyUnsafe = derivedKey)
        {
            try
            {
                using var aes = new AesGcm(derivedKey, TAG_SIZE_IN_BYTES);
                aes.Decrypt(nonce, ciphertext, tag, plaintext);
            }
            finally
            {
                Array.Clear(derivedKey);
            }
        }
    }
}

internal sealed class Pbkdf2ProviderShape
{
    private const int IterationCount = 100000;
    private const int SaltSizeInBytes = 16;
    private const int DerivedKeySizeInBytes = 32;

    // The static one-shot form, as ASP.NET Core's NetCorePbkdf2Provider uses it, but with the
    // values stated locally rather than passed in from a caller in another file.
    public byte[] DeriveKey(string password)
    {
        byte[] salt = new byte[SaltSizeInBytes];
        return Rfc2898DeriveBytes.Pbkdf2(
            password, salt, IterationCount, HashAlgorithmName.SHA256, DerivedKeySizeInBytes);
    }
}

internal sealed class LicenseSigningShape
{
    // A key size on a using declaration inside a loop, the Bitwarden self-host license pattern.
    public void GenerateKeys(int count)
    {
        for (int i = 0; i < count; i++)
        {
            using var rsa = RSA.Create(2048);
            byte[] data = new byte[64];
            byte[] signature = rsa.SignData(
                data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }

    // A signing key taken from a certificate, as Bitwarden's license verification does.
    public bool Verify(System.Security.Cryptography.X509Certificates.X509Certificate2 certificate)
    {
        using var rsa = certificate.GetRSAPublicKey();
        byte[] data = new byte[64];
        byte[] signature = new byte[256];
        return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
}

internal static class RandomShape
{
    // A stack-allocated span filled by the platform generator.
    public static void Fill()
    {
        Span<byte> buffer = stackalloc byte[32];
        RandomNumberGenerator.Fill(buffer);
    }
}

internal sealed class SplitConstructShape
{
    // A conditional that splits one expression-bodied member across its branches, taken verbatim
    // in shape from Microsoft.IdentityModel. With every branch active this is not valid C#, so the
    // parse fails and the file would be lost. The parser falls back to one branch per chain, which
    // is what a compiler sees for one build configuration and therefore always parses.
    public static string ClientSku =>
#if NET462
        "ID_NET462";
#elif NET472
        "ID_NET472";
#else
        "ID_NETSTANDARD2_0";
#endif

    // Cryptography after the split construct. This is what was being lost.
    public void SignAfterSplitConstruct()
    {
        using var rsa = RSA.Create(4096);
        byte[] data = new byte[64];
        byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
    }
}

#endif
