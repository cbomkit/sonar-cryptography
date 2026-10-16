/*
 * Comprehensive test file for System.Security.Cryptography ECDsa detection rules.
 *
 * Covers all three ECDsa-related classes and their complete operational API surface:
 *   - ECDsa (abstract base)
 *   - ECDsaCng, ECDsaOpenSsl (derived from ECDsa)
 *
 * Architecture note: all methods inherited from ECDsa / AsymmetricAlgorithm (KeySize,
 * SignData, VerifyData, SignHash, VerifyHash, Try* variants, etc.) are covered once here.
 * The detection engine tracks the variable and fires the same depending rules for every
 * concrete ECDsa subclass. Unlike RSA, ECDSA has no Encrypt/Decrypt operations.
 *
 * One rule covers all four ECDsaCng constructor overloads: ECDsaCng(), ECDsaCng(CngKey),
 * ECDsaCng(ECCurve), ECDsaCng(int). The single argument position holds unrelated things in each,
 * so it is read by value: an int is a key size, an ECCurve.NamedCurves member is a curve, and a
 * CngKey variable is neither and must leave both absent.
 */

using System.Security.Cryptography;

public class DotNetECDsaTest
{
    // -------------------------------------------------------------------------
    // Section 1: Factory methods / constructors
    // -------------------------------------------------------------------------

    public void TestECDsaCreate()
    {
        var ecdsa = ECDsa.Create(); // Noncompliant
    }

    public void TestECDsaCreateWithCurve()
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    }

    public void TestECDsaCng()
    {
        var ecdsa = new ECDsaCng();
    }

    public void TestECDsaOpenSsl()
    {
        var ecdsa = new ECDsaOpenSsl();
    }

    public void TestECDsaCngWithKey()
    {
        CngKey cngKey = null;
        var ecdsa = new ECDsaCng(cngKey);
    }

    public void TestECDsaCngWithCurve()
    {
        var ecdsa = new ECDsaCng(ECCurve.NamedCurves.nistP521);
    }

    public void TestECDsaCngWithKeySize()
    {
        var ecdsa = new ECDsaCng(521);
    }

    // -------------------------------------------------------------------------
    // Section 2: Property setters (via assignment → synthetic set_X invocations)
    // -------------------------------------------------------------------------

    public void TestPropertyKeySize256()
    {
        var ecdsa = ECDsa.Create();
        ecdsa.KeySize = 256;
    }

    public void TestPropertyKeySize384()
    {
        var ecdsa = ECDsa.Create();
        ecdsa.KeySize = 384;
    }

    // -------------------------------------------------------------------------
    // Section 3: SignData / TrySignData / VerifyData
    // -------------------------------------------------------------------------

    public void TestSignData()
    {
        var ecdsa = ECDsa.Create();
        byte[] data = new byte[64];
        byte[] signature = ecdsa.SignData(data, HashAlgorithmName.SHA256);
    }

    public void TestTrySignData()
    {
        var ecdsa = ECDsa.Create();
        byte[] data = new byte[64];
        byte[] destination = new byte[256];
        int bytesWritten;
        ecdsa.TrySignData(data, destination, HashAlgorithmName.SHA256, out bytesWritten);
    }

    public void TestVerifyData()
    {
        var ecdsa = ECDsa.Create();
        byte[] data = new byte[64];
        byte[] signature = new byte[256];
        bool valid = ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
    }

    // -------------------------------------------------------------------------
    // Section 4: SignHash / TrySignHash / VerifyHash
    // -------------------------------------------------------------------------

    public void TestSignHash()
    {
        var ecdsa = ECDsa.Create();
        byte[] hash = new byte[32];
        byte[] signature = ecdsa.SignHash(hash);
    }

    public void TestTrySignHash()
    {
        var ecdsa = ECDsa.Create();
        byte[] hash = new byte[32];
        byte[] destination = new byte[256];
        int bytesWritten;
        ecdsa.TrySignHash(hash, destination, out bytesWritten);
    }

    public void TestVerifyHash()
    {
        var ecdsa = ECDsa.Create();
        byte[] hash = new byte[32];
        byte[] signature = new byte[256];
        bool valid = ecdsa.VerifyHash(hash, signature);
    }

    // -------------------------------------------------------------------------
    // Section 5: Combined usage patterns (real-world scenarios)
    // Demonstrates that depending rules fire correctly for ALL derived classes.
    // -------------------------------------------------------------------------

    public void TestECDsaCngFullFlow()
    {
        var ecdsa = new ECDsaCng();
        ecdsa.KeySize = 384;
        byte[] data = new byte[64];
        byte[] signature = ecdsa.SignData(data, HashAlgorithmName.SHA384);
    }

    public void TestECDsaOpenSslVerifyFlow()
    {
        var ecdsa = new ECDsaOpenSsl();
        byte[] data = new byte[64];
        byte[] signature = new byte[256];
        bool valid = ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
    }

    // -------------------------------------------------------------------------
    // Section 6: parameter forms — offsets, keywords, curves by friendly name,
    // and values that must stay unresolved
    // -------------------------------------------------------------------------

    // SignData(data, offset, count, hashAlgorithm): the hash sits at index three here, not one.
    public void TestSignDataWithOffset()
    {
        var ecdsa = ECDsa.Create();
        byte[] data = new byte[64];
        byte[] signature = ecdsa.SignData(data, 0, 32, HashAlgorithmName.SHA512);
    }

    // VerifyData(data, offset, count, signature, hashAlgorithm)
    public void TestVerifyDataWithOffset()
    {
        var ecdsa = ECDsa.Create();
        byte[] data = new byte[64];
        byte[] signature = new byte[256];
        bool valid = ecdsa.VerifyData(data, 0, 32, signature, HashAlgorithmName.SHA384);
    }

    // The hash written as a keyword argument, before the positional ones it follows in the
    // signature would allow.
    public void TestSignDataNamedHash()
    {
        var ecdsa = ECDsa.Create();
        byte[] data = new byte[64];
        byte[] signature = ecdsa.SignData(data, hashAlgorithm: HashAlgorithmName.SHA384);
    }

    // A curve given by friendly name rather than as an ECCurve.NamedCurves member.
    public void TestECDsaCreateFromFriendlyName()
    {
        var ecdsa = ECDsa.Create(ECCurve.CreateFromFriendlyName("secp256k1"));
    }

    // A named curve reached through a local variable.
    public void TestECDsaCreateCurveFromLocal()
    {
        var curve = ECCurve.NamedCurves.nistP384;
        var ecdsa = ECDsa.Create(curve);
    }

    // ECDsaOpenSsl(int) — the key size overload of the OpenSSL-backed class.
    public void TestECDsaOpenSslWithKeySize()
    {
        var ecdsa = new ECDsaOpenSsl(384);
    }

    // ECParameters is neither a key size nor a named curve: both must stay absent while ECDSA
    // itself is still reported.
    public void TestECDsaCreateFromParameters()
    {
        ECParameters parameters = default;
        var ecdsa = ECDsa.Create(parameters);
    }

    // The hash algorithm arrives as a method parameter whose callers disagree, so no digest may
    // be attached to the signing operation.
    public void TestSignDataUnknownHash(HashAlgorithmName algorithm)
    {
        var ecdsa = ECDsa.Create();
        byte[] data = new byte[64];
        byte[] signature = ecdsa.SignData(data, algorithm);
    }

    public void CallSignDataUnknownHashSha256()
    {
        TestSignDataUnknownHash(HashAlgorithmName.SHA256);
    }

    public void CallSignDataUnknownHashSha384()
    {
        TestSignDataUnknownHash(HashAlgorithmName.SHA384);
    }
}
