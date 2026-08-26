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
 */

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
}
