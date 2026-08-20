/*
 * Comprehensive test file for System.Security.Cryptography Triple DES (3DES) detection rules.
 *
 * Covers all three TripleDES-related classes and their complete API surface:
 *   - TripleDES (abstract base)
 *   - TripleDESCryptoServiceProvider (derived from TripleDES, legacy CAPI)
 *   - TripleDESCng (derived from TripleDES, CNG-backed)
 *
 * Architecture note: all methods inherited from SymmetricAlgorithm (EncryptCbc,
 * CreateEncryptor, etc.) are covered once here. The detection engine tracks the
 * variable and fires the same depending rules for every concrete TripleDES subclass.
 * Unlike RC2, TripleDES exposes no extra properties beyond those inherited from
 * SymmetricAlgorithm, so Section 2 mirrors DotNetDESComprehensiveTestFile.cs. Unlike
 * DES/RC2 (which have no CNG-backed subclass), TripleDES has TripleDESCng, mirroring
 * AesCng in DotNetAESComprehensiveTestFile.cs.
 */

using System.Security.Cryptography;

public class DotNetTripleDESComprehensiveTest
{
    // -------------------------------------------------------------------------
    // Section 1: Factory methods / constructors
    // -------------------------------------------------------------------------

    public void TestTripleDesCreate()
    {
        var tdes = TripleDES.Create();
    }

    public void TestTripleDesCreateNamed()
    {
        var tdes = TripleDES.Create("TripleDES");
    }

    public void TestTripleDesCsp()
    {
        var tdes = new TripleDESCryptoServiceProvider();
    }

    public void TestTripleDesCng()
    {
        var tdes = new TripleDESCng();
    }

    public void TestTripleDesCngNamed()
    {
        var tdes = new TripleDESCng("myKey");
    }

    // -------------------------------------------------------------------------
    // Section 2: Property setters (via assignment → synthetic set_X invocations)
    // -------------------------------------------------------------------------

    public void TestPropertyModeCBC()
    {
        var tdes = TripleDES.Create();
        tdes.Mode = CipherMode.CBC;
    }

    public void TestPropertyModeECB()
    {
        var tdes = TripleDES.Create();
        tdes.Mode = CipherMode.ECB;
    }

    public void TestPropertyModeCFB()
    {
        var tdes = TripleDES.Create();
        tdes.Mode = CipherMode.CFB;
    }

    public void TestPropertyModeOFB()
    {
        var tdes = TripleDES.Create();
        tdes.Mode = CipherMode.OFB;
    }

    public void TestPropertyModeCTS()
    {
        var tdes = TripleDES.Create();
        tdes.Mode = CipherMode.CTS;
    }

    public void TestPropertyKeySize()
    {
        var tdes = TripleDES.Create();
        tdes.KeySize = 192;
    }

    public void TestPropertyPaddingPKCS7()
    {
        var tdes = TripleDES.Create();
        tdes.Padding = PaddingMode.PKCS7;
    }

    public void TestPropertyPaddingNone()
    {
        var tdes = TripleDES.Create();
        tdes.Padding = PaddingMode.None;
    }

    public void TestPropertyPaddingZeros()
    {
        var tdes = TripleDES.Create();
        tdes.Padding = PaddingMode.Zeros;
    }

    public void TestPropertyPaddingANSIX923()
    {
        var tdes = TripleDES.Create();
        tdes.Padding = PaddingMode.ANSIX923;
    }

    public void TestPropertyFeedbackSize()
    {
        var tdes = TripleDES.Create();
        tdes.FeedbackSize = 8;
    }

    public void TestPropertyIV()
    {
        var tdes = TripleDES.Create();
        tdes.IV = new byte[8];
    }

    public void TestPropertyKey()
    {
        var tdes = TripleDES.Create();
        tdes.Key = new byte[24];
    }

    // -------------------------------------------------------------------------
    // Section 3: CreateEncryptor / CreateDecryptor
    // -------------------------------------------------------------------------

    public void TestCreateEncryptorNoArgs()
    {
        var tdes = TripleDES.Create();
        var encryptor = tdes.CreateEncryptor();
    }

    public void TestCreateEncryptorWithArgs()
    {
        var tdes = TripleDES.Create();
        byte[] key = new byte[24];
        byte[] iv = new byte[8];
        var encryptor = tdes.CreateEncryptor(key, iv);
    }

    public void TestCreateDecryptorNoArgs()
    {
        var tdes = TripleDES.Create();
        var decryptor = tdes.CreateDecryptor();
    }

    public void TestCreateDecryptorWithArgs()
    {
        var tdes = TripleDES.Create();
        byte[] key = new byte[24];
        byte[] iv = new byte[8];
        var decryptor = tdes.CreateDecryptor(key, iv);
    }

    // -------------------------------------------------------------------------
    // Section 4: Direct mode-specific encrypt methods
    // -------------------------------------------------------------------------

    public void TestEncryptCbc()
    {
        var tdes = TripleDES.Create();
        byte[] plaintext = new byte[16];
        byte[] iv = new byte[8];
        byte[] ciphertext = tdes.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);
    }

    public void TestEncryptEcb()
    {
        var tdes = TripleDES.Create();
        byte[] plaintext = new byte[16];
        byte[] ciphertext = tdes.EncryptEcb(plaintext, PaddingMode.None);
    }

    public void TestEncryptCfb()
    {
        var tdes = TripleDES.Create();
        byte[] plaintext = new byte[16];
        byte[] iv = new byte[8];
        byte[] ciphertext = tdes.EncryptCfb(plaintext, iv, PaddingMode.None, 8);
    }

    // -------------------------------------------------------------------------
    // Section 5: Direct mode-specific decrypt methods
    // -------------------------------------------------------------------------

    public void TestDecryptCbc()
    {
        var tdes = TripleDES.Create();
        byte[] ciphertext = new byte[16];
        byte[] iv = new byte[8];
        byte[] plaintext = tdes.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
    }

    public void TestDecryptEcb()
    {
        var tdes = TripleDES.Create();
        byte[] ciphertext = new byte[16];
        byte[] plaintext = tdes.DecryptEcb(ciphertext, PaddingMode.None);
    }

    public void TestDecryptCfb()
    {
        var tdes = TripleDES.Create();
        byte[] ciphertext = new byte[16];
        byte[] iv = new byte[8];
        byte[] plaintext = tdes.DecryptCfb(ciphertext, iv, PaddingMode.None, 8);
    }

    // -------------------------------------------------------------------------
    // Section 6: Try* variants
    // -------------------------------------------------------------------------

    public void TestTryEncryptCbc()
    {
        var tdes = TripleDES.Create();
        byte[] plaintext = new byte[16];
        byte[] iv = new byte[8];
        byte[] destination = new byte[24];
        int bytesWritten;
        tdes.TryEncryptCbc(plaintext, iv, destination, out bytesWritten, PaddingMode.PKCS7);
    }

    public void TestTryDecryptCbc()
    {
        var tdes = TripleDES.Create();
        byte[] ciphertext = new byte[16];
        byte[] iv = new byte[8];
        byte[] destination = new byte[16];
        int bytesWritten;
        tdes.TryDecryptCbc(ciphertext, iv, destination, out bytesWritten, PaddingMode.PKCS7);
    }

    public void TestTryEncryptEcb()
    {
        var tdes = TripleDES.Create();
        byte[] plaintext = new byte[16];
        byte[] destination = new byte[24];
        int bytesWritten;
        tdes.TryEncryptEcb(plaintext, destination, PaddingMode.None, out bytesWritten);
    }

    public void TestTryDecryptEcb()
    {
        var tdes = TripleDES.Create();
        byte[] ciphertext = new byte[16];
        byte[] destination = new byte[16];
        int bytesWritten;
        tdes.TryDecryptEcb(ciphertext, destination, PaddingMode.None, out bytesWritten);
    }

    public void TestTryEncryptCfb()
    {
        var tdes = TripleDES.Create();
        byte[] plaintext = new byte[16];
        byte[] iv = new byte[8];
        byte[] destination = new byte[24];
        int bytesWritten;
        tdes.TryEncryptCfb(plaintext, iv, destination, out bytesWritten, PaddingMode.None, 8);
    }

    public void TestTryDecryptCfb()
    {
        var tdes = TripleDES.Create();
        byte[] ciphertext = new byte[16];
        byte[] iv = new byte[8];
        byte[] destination = new byte[16];
        int bytesWritten;
        tdes.TryDecryptCfb(ciphertext, iv, destination, out bytesWritten, PaddingMode.None, 8);
    }

    // -------------------------------------------------------------------------
    // Section 7: Key/IV generation
    // -------------------------------------------------------------------------

    public void TestGenerateKey()
    {
        var tdes = TripleDES.Create();
        tdes.GenerateKey();
    }

    public void TestGenerateIV()
    {
        var tdes = TripleDES.Create();
        tdes.GenerateIV();
    }

    // -------------------------------------------------------------------------
    // Section 8: Combined usage patterns (real-world scenarios)
    // Demonstrates that depending rules fire correctly for all derived classes.
    // -------------------------------------------------------------------------

    public void TestTripleDesCbcFullFlow()
    {
        var tdes = TripleDES.Create();
        tdes.Mode = CipherMode.CBC;
        tdes.Padding = PaddingMode.PKCS7;
        var encryptor = tdes.CreateEncryptor();
    }

    public void TestTripleDesCspEncryptCbc()
    {
        var tdes = new TripleDESCryptoServiceProvider();
        tdes.Mode = CipherMode.CBC;
        byte[] plaintext = new byte[16];
        byte[] iv = new byte[8];
        byte[] ciphertext = tdes.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);
    }

    public void TestTripleDesCspDecryptCbc()
    {
        var tdes = new TripleDESCryptoServiceProvider();
        byte[] ciphertext = new byte[16];
        byte[] iv = new byte[8];
        byte[] plaintext = tdes.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
    }

    public void TestTripleDesCfbFeedback()
    {
        var tdes = TripleDES.Create();
        tdes.Mode = CipherMode.CFB;
        tdes.FeedbackSize = 8;
        byte[] plaintext = new byte[16];
        byte[] iv = new byte[8];
        byte[] ciphertext = tdes.EncryptCfb(plaintext, iv, PaddingMode.None, 8);
    }

    public void TestTripleDesCbcWithEncryptorOverload()
    {
        var tdes = TripleDES.Create();
        byte[] key = new byte[24];
        byte[] iv = new byte[8];
        var encryptor = tdes.CreateEncryptor(key, iv);
    }

    public void TestTripleDesEcbEncrypt()
    {
        var tdes = new TripleDESCryptoServiceProvider();
        byte[] plaintext = new byte[16];
        byte[] ciphertext = tdes.EncryptEcb(plaintext, PaddingMode.None);
    }

    public void TestTripleDesCngEncryptCbc()
    {
        var tdes = new TripleDESCng();
        byte[] plaintext = new byte[16];
        byte[] iv = new byte[8];
        byte[] ciphertext = tdes.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);
    }
}
