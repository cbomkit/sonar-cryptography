/*
 * Comprehensive test file for System.Security.Cryptography KDF-family detection rules
 * (DotNetKeyDerivation.java), excluding Rfc2898DeriveBytes (covered separately in
 * DotNetRfc2898DeriveBytesTestFile.cs).
 *
 * Covers:
 *   - HKDF (static-only class: Extract, Expand, DeriveKey)
 *   - SP800108HmacCounterKdf (constructor + instance DeriveKey, and the static DeriveBytes
 *     one-shot overload)
 *   - PasswordDeriveBytes (constructor + instance GetBytes / CryptDeriveKey)
 *
 * Each family is exercised in its array form, in its span form (where the .NET API offers one and
 * the span sits where an int sits in the array form), with keyword arguments written out of
 * declared order, and with at least one value that cannot be resolved and must therefore stay
 * absent.
 */

using System;
using System.Security.Cryptography;

public class DotNetKeyDerivationTest
{
    // -------------------------------------------------------------------------
    // Section 1: HKDF (static-only, no instance)
    // -------------------------------------------------------------------------

    public void TestHkdfExtract()
    {
        byte[] ikm = new byte[32];
        byte[] salt = new byte[16];
        byte[] prk = HKDF.Extract(HashAlgorithmName.SHA256, ikm, salt);
    }

    public void TestHkdfExpand()
    {
        byte[] prk = new byte[32];
        byte[] info = new byte[8];
        byte[] okm = HKDF.Expand(HashAlgorithmName.SHA256, prk, 32, info);
    }

    public void TestHkdfDeriveKey()
    {
        byte[] ikm = new byte[32];
        byte[] salt = new byte[16];
        byte[] info = new byte[8];
        byte[] key = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 32, salt, info);
    }

    // -------------------------------------------------------------------------
    // Section 2: SP800108HmacCounterKdf
    // -------------------------------------------------------------------------

    public void TestSp800108CtorAndDeriveKey()
    {
        byte[] key = new byte[32];
        var kdf = new SP800108HmacCounterKdf(key, HashAlgorithmName.SHA256);
        byte[] label = new byte[8];
        byte[] context = new byte[8];
        byte[] derived = kdf.DeriveKey(label, context, 32);
    }

    public void TestSp800108StaticDeriveBytes()
    {
        byte[] key = new byte[32];
        byte[] label = new byte[8];
        byte[] context = new byte[8];
        byte[] derived = SP800108HmacCounterKdf.DeriveBytes(
            key, HashAlgorithmName.SHA256, label, context, 32);
    }

    // -------------------------------------------------------------------------
    // Section 3: PasswordDeriveBytes
    // -------------------------------------------------------------------------

    public void TestPasswordDeriveBytesGetBytes()
    {
        byte[] salt = new byte[16];
        var pdb = new PasswordDeriveBytes("password", salt);
        byte[] derived = pdb.GetBytes(16);
    }

    public void TestPasswordDeriveBytesCryptDeriveKey()
    {
        byte[] salt = new byte[16];
        var pdb = new PasswordDeriveBytes("password", salt, "SHA1", 100);
        byte[] iv = new byte[8];
        byte[] key = pdb.CryptDeriveKey("TripleDES", "SHA1", 192, iv);
    }

    public void TestPasswordDeriveBytesProperties()
    {
        byte[] salt = new byte[16];
        var pdb = new PasswordDeriveBytes("password", salt);
        pdb.IterationCount = 100000;
        pdb.HashName = "SHA256";
    }

    // -------------------------------------------------------------------------
    // Section 4: span overloads, keyword arguments, and unresolvable values
    // -------------------------------------------------------------------------

    // HKDF.Extract(hashAlgorithmName, ikm, salt, prk) — the four-parameter span form.
    public void TestHkdfExtractSpan()
    {
        Span<byte> prk = stackalloc byte[32];
        HKDF.Extract(HashAlgorithmName.SHA384, new byte[32], new byte[8], prk);
    }

    // HKDF.Expand(hashAlgorithmName, prk, output, info) — the span form puts a Span where the
    // array form puts outputLength, so no output length may be reported here.
    public void TestHkdfExpandSpanOutput()
    {
        Span<byte> output = stackalloc byte[64];
        HKDF.Expand(HashAlgorithmName.SHA512, new byte[32], output, new byte[8]);
    }

    // HKDF.DeriveKey(hashAlgorithmName, ikm, output, salt, info) — same for DeriveKey: the salt
    // length is still readable, the output length is not.
    public void TestHkdfDeriveKeySpanOutput()
    {
        Span<byte> output = stackalloc byte[48];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, new byte[32], output, new byte[24], new byte[8]);
    }

    // Keyword arguments in the reverse of the declared order.
    public void TestHkdfDeriveKeyNamedReordered()
    {
        byte[] key = HKDF.DeriveKey(
            info: new byte[8],
            salt: new byte[20],
            outputLength: 64,
            ikm: new byte[32],
            hashAlgorithmName: HashAlgorithmName.SHA384);
    }

    // Salt length arrives through a const field and a local that aliases it.
    public void TestHkdfFromConstants()
    {
        int outputBytes = DerivedBytes;
        byte[] key = HKDF.DeriveKey(HashAlgorithmName.SHA512, new byte[32], outputBytes, ConstSalt, new byte[8]);
    }

    private const int DerivedBytes = 48;
    private static readonly byte[] ConstSalt = new byte[64];

    // The salt comes from a call this engine cannot see into: HKDF and its hash must still be
    // reported, the salt length must not.
    public void TestHkdfUnknownSalt()
    {
        byte[] salt = Convert.FromBase64String(Environment.GetEnvironmentVariable("SALT"));
        byte[] key = HKDF.DeriveKey(HashAlgorithmName.SHA256, new byte[32], 32, salt, new byte[8]);
    }

    // SP800-108 with keyword arguments out of order.
    public void TestSp800108NamedReordered()
    {
        byte[] derived = SP800108HmacCounterKdf.DeriveBytes(
            derivedKeyLengthInBytes: 64,
            hashAlgorithm: HashAlgorithmName.SHA384,
            key: new byte[32],
            label: new byte[8],
            context: new byte[8]);
    }

    // PasswordDeriveBytes with the full five-parameter form, hash name and iteration count given.
    public void TestPasswordDeriveBytesFullForm()
    {
        var pdb = new PasswordDeriveBytes("password", new byte[16], "SHA256", 20000, null);
        byte[] derived = pdb.GetBytes(24);
    }
}
