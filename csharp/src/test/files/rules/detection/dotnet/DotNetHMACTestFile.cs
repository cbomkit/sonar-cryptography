/*
 * Test file for the System.Security.Cryptography HMAC detection rules.
 *
 * Every HMAC class has a parameterless constructor, which generates a random key, and a
 * constructor taking the key. Where the key is an array whose length the engine can read, that
 * length is the MAC key length and is recorded; where it cannot, only the algorithm is.
 */

using System.Security.Cryptography;

public class DotNetHMACTest {
    // --- parameterless: a random key of the algorithm's default length, nothing to record ------

    public void TestHmacSha1()   { var h = new HMACSHA1(); }   // Noncompliant
    public void TestHmacSha256() { var h = new HMACSHA256(); } // Noncompliant
    public void TestHmacSha384() { var h = new HMACSHA384(); } // Noncompliant
    public void TestHmacSha512() { var h = new HMACSHA512(); } // Noncompliant
    public void TestHmacMd5()    { var h = new HMACMD5(); }    // Noncompliant
    public void TestHmacRipemd160() { var h = new HMACRIPEMD160(); } // Noncompliant
    public void TestHmacSha3_256()  { var h = new HMACSHA3_256(); }  // Noncompliant
    public void TestHmacSha3_384()  { var h = new HMACSHA3_384(); }  // Noncompliant
    public void TestHmacSha3_512()  { var h = new HMACSHA3_512(); }  // Noncompliant
    public void TestMacTripleDes()  { var h = new MACTripleDES(); }  // Noncompliant

    // --- with a key whose length is readable ---------------------------------------------------

    public void TestHmacSha256WithKey()
    {
        var h = new HMACSHA256(new byte[32]);
    }

    public void TestHmacSha512WithKeyFromLocal()
    {
        byte[] key = new byte[64];
        var h = new HMACSHA512(key);
    }

    public void TestHmacSha256WithKeyFromConstField()
    {
        var h = new HMACSHA256(FixedKey);
    }

    private static readonly byte[] FixedKey = new byte[16];

    public void TestMacTripleDesWithKey()
    {
        var h = new MACTripleDES(new byte[24]);
    }

    // --- with a key the engine cannot measure: only the algorithm may be reported --------------

    public void TestHmacSha256WithUnknownKey()
    {
        byte[] key = LoadKeyFromKeyStore();
        var h = new HMACSHA256(key);
    }

    private byte[] LoadKeyFromKeyStore()
    {
        return System.Convert.FromBase64String(
            System.Environment.GetEnvironmentVariable("HMAC_KEY"));
    }
}
