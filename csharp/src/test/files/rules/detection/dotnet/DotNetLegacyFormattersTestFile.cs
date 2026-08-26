/*
 * Test file for the legacy Formatter/Deformatter and mask-generation detection rules
 * (DotNetLegacyFormatters.java).
 *
 * Covers all nine classes:
 *   - DSASignatureFormatter / DSASignatureDeformatter
 *   - RSAPKCS1SignatureFormatter / RSAPKCS1SignatureDeformatter
 *   - RSAOAEPKeyExchangeFormatter / RSAOAEPKeyExchangeDeformatter
 *   - RSAPKCS1KeyExchangeFormatter / RSAPKCS1KeyExchangeDeformatter
 *   - PKCS1MaskGenerationMethod
 *
 * Note: the parameterless constructor overload is used throughout (rather than passing a
 * DSA/RSA instance from DSA.Create()/RSA.Create()) so that each test method exercises exactly
 * this file's rules in isolation, without also triggering DotNetDSA.java's/DotNetRSA.java's own
 * DSA.Create()/RSA.Create() detection rules. This also directly demonstrates the documented
 * SetKey gap: the Formatter/Deformatter is detected purely from its own class name, independent
 * of whether (or how) a real key was ever wired up via SetKey.
 */

using System.Security.Cryptography;

public class DotNetLegacyFormattersTest
{
    // -------------------------------------------------------------------------
    // DSASignatureFormatter / DSASignatureDeformatter
    // -------------------------------------------------------------------------

    public void TestDsaSignatureFormatterCreateSignature()
    {
        var formatter = new DSASignatureFormatter(); // Noncompliant
        byte[] hash = new byte[20];
        byte[] signature = formatter.CreateSignature(hash);
    }

    public void TestDsaSignatureFormatterSetHashAlgorithm()
    {
        var formatter = new DSASignatureFormatter();
        formatter.SetHashAlgorithm("SHA1");
    }

    public void TestDsaSignatureDeformatterVerifySignature()
    {
        var deformatter = new DSASignatureDeformatter();
        byte[] hash = new byte[20];
        byte[] signature = new byte[40];
        bool valid = deformatter.VerifySignature(hash, signature);
    }

    // -------------------------------------------------------------------------
    // RSAPKCS1SignatureFormatter / RSAPKCS1SignatureDeformatter
    // -------------------------------------------------------------------------

    public void TestRsaPkcs1SignatureFormatterCreateSignature()
    {
        var formatter = new RSAPKCS1SignatureFormatter();
        byte[] hash = new byte[32];
        byte[] signature = formatter.CreateSignature(hash);
    }

    public void TestRsaPkcs1SignatureFormatterSetHashAlgorithm()
    {
        var formatter = new RSAPKCS1SignatureFormatter();
        formatter.SetHashAlgorithm("SHA256");
    }

    public void TestRsaPkcs1SignatureDeformatterVerifySignature()
    {
        var deformatter = new RSAPKCS1SignatureDeformatter();
        byte[] hash = new byte[32];
        byte[] signature = new byte[256];
        bool valid = deformatter.VerifySignature(hash, signature);
    }

    // -------------------------------------------------------------------------
    // RSAOAEPKeyExchangeFormatter / RSAOAEPKeyExchangeDeformatter
    // -------------------------------------------------------------------------

    public void TestRsaOaepKeyExchangeFormatterCreateKeyExchange1()
    {
        var formatter = new RSAOAEPKeyExchangeFormatter();
        byte[] key = new byte[32];
        byte[] encryptedKey = formatter.CreateKeyExchange(key);
    }

    public void TestRsaOaepKeyExchangeFormatterCreateKeyExchange2()
    {
        var formatter = new RSAOAEPKeyExchangeFormatter();
        byte[] key = new byte[32];
        byte[] encryptedKey = formatter.CreateKeyExchange(key, typeof(Aes));
    }

    public void TestRsaOaepKeyExchangeDeformatterDecryptKeyExchange()
    {
        var deformatter = new RSAOAEPKeyExchangeDeformatter();
        byte[] encryptedKey = new byte[256];
        byte[] key = deformatter.DecryptKeyExchange(encryptedKey);
    }

    // -------------------------------------------------------------------------
    // RSAPKCS1KeyExchangeFormatter / RSAPKCS1KeyExchangeDeformatter
    // -------------------------------------------------------------------------

    public void TestRsaPkcs1KeyExchangeFormatterCreateKeyExchange1()
    {
        var formatter = new RSAPKCS1KeyExchangeFormatter();
        byte[] key = new byte[32];
        byte[] encryptedKey = formatter.CreateKeyExchange(key);
    }

    public void TestRsaPkcs1KeyExchangeFormatterCreateKeyExchange2()
    {
        var formatter = new RSAPKCS1KeyExchangeFormatter();
        byte[] key = new byte[32];
        byte[] encryptedKey = formatter.CreateKeyExchange(key, typeof(Aes));
    }

    public void TestRsaPkcs1KeyExchangeDeformatterDecryptKeyExchange()
    {
        var deformatter = new RSAPKCS1KeyExchangeDeformatter();
        byte[] encryptedKey = new byte[256];
        byte[] key = deformatter.DecryptKeyExchange(encryptedKey);
    }

    // -------------------------------------------------------------------------
    // PKCS1MaskGenerationMethod
    // -------------------------------------------------------------------------

    public void TestPkcs1MaskGenerationMethodCreate()
    {
        var mgf = new PKCS1MaskGenerationMethod();
    }

    public void TestPkcs1MaskGenerationMethodSetHashName()
    {
        var mgf = new PKCS1MaskGenerationMethod();
        mgf.HashName = "SHA256";
    }
}
