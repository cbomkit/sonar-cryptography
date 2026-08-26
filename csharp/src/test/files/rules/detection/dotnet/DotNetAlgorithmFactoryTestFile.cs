/*
 * Test file for the generic, string-based Create(string) factory methods declared directly on
 * the abstract base classes of System.Security.Cryptography (DotNetAlgorithmFactory.java):
 *   - SymmetricAlgorithm.Create(string)
 *   - HashAlgorithm.Create(string)
 *   - KeyedHashAlgorithm.Create(string)
 *   - HMAC.Create(string)
 *   - AsymmetricAlgorithm.Create(string)
 */

using System.Security.Cryptography;

public class DotNetAlgorithmFactoryTest
{
    // -------------------------------------------------------------------------
    // SymmetricAlgorithm.Create(string algName)
    // -------------------------------------------------------------------------

    public void TestSymmetricAlgorithmCreateAes()
    {
        SymmetricAlgorithm alg = SymmetricAlgorithm.Create("AES");
    }

    public void TestSymmetricAlgorithmCreateRc2()
    {
        SymmetricAlgorithm alg = SymmetricAlgorithm.Create("RC2");
    }

    public void TestSymmetricAlgorithmCreateTripleDes()
    {
        SymmetricAlgorithm alg = SymmetricAlgorithm.Create("3DES");
    }

    public void TestSymmetricAlgorithmCreateDes()
    {
        SymmetricAlgorithm alg = SymmetricAlgorithm.Create("DES");
    }

    // SymmetricAlgorithm.Create(string) followed by CreateEncryptor/CreateDecryptor: verifies that
    // the generic, algorithm-independent depending rules attached to SYMMETRIC_ALGORITHM_CREATE
    // (mirroring DotNetAES/DotNetRC2's CIPHER_OP_RULES) fire on the tracked variable.
    public void TestSymmetricAlgorithmCreateAesWithEncryptorAndDecryptor()
    {
        var alg = SymmetricAlgorithm.Create("AES");
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        var enc = alg.CreateEncryptor(key, iv);
        var dec = alg.CreateDecryptor(key, iv);
    }

    // -------------------------------------------------------------------------
    // HashAlgorithm.Create(string hashName)
    // -------------------------------------------------------------------------

    public void TestHashAlgorithmCreateSha256()
    {
        HashAlgorithm alg = HashAlgorithm.Create("SHA256");
    }

    public void TestHashAlgorithmCreateShaHyphenated()
    {
        HashAlgorithm alg = HashAlgorithm.Create("SHA-512");
    }

    public void TestHashAlgorithmCreateMd5()
    {
        HashAlgorithm alg = HashAlgorithm.Create("MD5");
    }

    public void TestHashAlgorithmCreateShaBare()
    {
        HashAlgorithm alg = HashAlgorithm.Create("SHA");
    }

    // -------------------------------------------------------------------------
    // KeyedHashAlgorithm.Create(string algName)
    // -------------------------------------------------------------------------

    public void TestKeyedHashAlgorithmCreateHmacSha256()
    {
        KeyedHashAlgorithm alg = KeyedHashAlgorithm.Create("HMACSHA256");
    }

    public void TestKeyedHashAlgorithmCreateMacTripleDes()
    {
        KeyedHashAlgorithm alg = KeyedHashAlgorithm.Create("MACTripleDES");
    }

    // -------------------------------------------------------------------------
    // HMAC.Create(string algorithmName)
    // -------------------------------------------------------------------------

    public void TestHmacCreateHmacSha1()
    {
        HMAC alg = HMAC.Create("HMACSHA1");
    }

    public void TestHmacCreateFullyQualified()
    {
        HMAC alg = HMAC.Create("System.Security.Cryptography.HMACSHA256");
    }

    // -------------------------------------------------------------------------
    // AsymmetricAlgorithm.Create(string algName)
    // -------------------------------------------------------------------------

    public void TestAsymmetricAlgorithmCreateRsa()
    {
        AsymmetricAlgorithm alg = AsymmetricAlgorithm.Create("RSA");
    }

    public void TestAsymmetricAlgorithmCreateDsa()
    {
        AsymmetricAlgorithm alg = AsymmetricAlgorithm.Create("DSA");
    }

    public void TestAsymmetricAlgorithmCreateEcdsa()
    {
        AsymmetricAlgorithm alg = AsymmetricAlgorithm.Create("ECDsa");
    }

    public void TestAsymmetricAlgorithmCreateEcdh()
    {
        AsymmetricAlgorithm alg = AsymmetricAlgorithm.Create("ECDH");
    }
}
