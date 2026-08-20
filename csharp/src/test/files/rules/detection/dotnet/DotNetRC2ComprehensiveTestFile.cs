/*
 * Comprehensive test file for System.Security.Cryptography RC2 detection rules.
 *
 * Covers both RC2-related classes and their complete API surface:
 *   - RC2 (abstract base)
 *   - RC2CryptoServiceProvider (derived from RC2)
 *
 * Like DES, RC2 has no CNG-backed subclass and no AEAD variant, so there are
 * fewer constructor scenarios in Section 1, and no AEAD sections. Unlike DES,
 * RC2 additionally exposes an EffectiveKeySize property (Section 2), which is
 * reused as a KeySize detection (see DotNetRC2.java).
 *
 * Architecture note: all methods inherited from SymmetricAlgorithm (EncryptCbc,
 * CreateEncryptor, etc.) are covered once here. The detection engine tracks the
 * variable and fires the same depending rules for every concrete RC2 subclass.
 */

using System.Security.Cryptography;

public class DotNetRC2ComprehensiveTest
{
    // -------------------------------------------------------------------------
    // Section 1: Factory methods / constructors
    // -------------------------------------------------------------------------

    public void TestRc2Create()
    {
        var rc2 = RC2.Create();
    }

    public void TestRc2CreateNamed()
    {
        var rc2 = RC2.Create("RC2");
    }

    public void TestRc2Csp()
    {
        var rc2 = new RC2CryptoServiceProvider();
    }

    // -------------------------------------------------------------------------
    // Section 2: Property setters (via assignment → synthetic set_X invocations)
    // -------------------------------------------------------------------------

    public void TestPropertyModeCBC()
    {
        var rc2 = RC2.Create();
        rc2.Mode = CipherMode.CBC;
    }

    public void TestPropertyModeECB()
    {
        var rc2 = RC2.Create();
        rc2.Mode = CipherMode.ECB;
    }

    public void TestPropertyModeCFB()
    {
        var rc2 = RC2.Create();
        rc2.Mode = CipherMode.CFB;
    }

    public void TestPropertyModeOFB()
    {
        var rc2 = RC2.Create();
        rc2.Mode = CipherMode.OFB;
    }

    public void TestPropertyModeCTS()
    {
        var rc2 = RC2.Create();
        rc2.Mode = CipherMode.CTS;
    }

    public void TestPropertyKeySize()
    {
        var rc2 = RC2.Create();
        rc2.KeySize = 128;
    }

    public void TestPropertyEffectiveKeySize()
    {
        var rc2 = RC2.Create();
        rc2.EffectiveKeySize = 64;
    }

    public void TestPropertyPaddingPKCS7()
    {
        var rc2 = RC2.Create();
        rc2.Padding = PaddingMode.PKCS7;
    }

    public void TestPropertyPaddingNone()
    {
        var rc2 = RC2.Create();
        rc2.Padding = PaddingMode.None;
    }

    public void TestPropertyPaddingZeros()
    {
        var rc2 = RC2.Create();
        rc2.Padding = PaddingMode.Zeros;
    }

    public void TestPropertyPaddingANSIX923()
    {
        var rc2 = RC2.Create();
        rc2.Padding = PaddingMode.ANSIX923;
    }

    public void TestPropertyFeedbackSize()
    {
        var rc2 = RC2.Create();
        rc2.FeedbackSize = 8;
    }

    public void TestPropertyIV()
    {
        var rc2 = RC2.Create();
        rc2.IV = new byte[8];
    }

    public void TestPropertyKey()
    {
        var rc2 = RC2.Create();
        rc2.Key = new byte[16];
    }

    // -------------------------------------------------------------------------
    // Section 3: CreateEncryptor / CreateDecryptor
    // -------------------------------------------------------------------------

    public void TestCreateEncryptorNoArgs()
    {
        var rc2 = RC2.Create();
        var encryptor = rc2.CreateEncryptor();
    }

    public void TestCreateEncryptorWithArgs()
    {
        var rc2 = RC2.Create();
        byte[] key = new byte[16];
        byte[] iv = new byte[8];
        var encryptor = rc2.CreateEncryptor(key, iv);
    }

    public void TestCreateDecryptorNoArgs()
    {
        var rc2 = RC2.Create();
        var decryptor = rc2.CreateDecryptor();
    }

    public void TestCreateDecryptorWithArgs()
    {
        var rc2 = RC2.Create();
        byte[] key = new byte[16];
        byte[] iv = new byte[8];
        var decryptor = rc2.CreateDecryptor(key, iv);
    }

    // -------------------------------------------------------------------------
    // Section 4: Direct mode-specific encrypt methods
    // -------------------------------------------------------------------------

    public void TestEncryptCbc()
    {
        var rc2 = RC2.Create();
        byte[] plaintext = new byte[16];
        byte[] iv = new byte[8];
        byte[] ciphertext = rc2.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);
    }

    public void TestEncryptEcb()
    {
        var rc2 = RC2.Create();
        byte[] plaintext = new byte[16];
        byte[] ciphertext = rc2.EncryptEcb(plaintext, PaddingMode.None);
    }

    public void TestEncryptCfb()
    {
        var rc2 = RC2.Create();
        byte[] plaintext = new byte[16];
        byte[] iv = new byte[8];
        byte[] ciphertext = rc2.EncryptCfb(plaintext, iv, PaddingMode.None, 8);
    }

    // -------------------------------------------------------------------------
    // Section 5: Direct mode-specific decrypt methods
    // -------------------------------------------------------------------------

    public void TestDecryptCbc()
    {
        var rc2 = RC2.Create();
        byte[] ciphertext = new byte[16];
        byte[] iv = new byte[8];
        byte[] plaintext = rc2.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
    }

    public void TestDecryptEcb()
    {
        var rc2 = RC2.Create();
        byte[] ciphertext = new byte[16];
        byte[] plaintext = rc2.DecryptEcb(ciphertext, PaddingMode.None);
    }

    public void TestDecryptCfb()
    {
        var rc2 = RC2.Create();
        byte[] ciphertext = new byte[16];
        byte[] iv = new byte[8];
        byte[] plaintext = rc2.DecryptCfb(ciphertext, iv, PaddingMode.None, 8);
    }

    // -------------------------------------------------------------------------
    // Section 6: Try* variants
    // -------------------------------------------------------------------------

    public void TestTryEncryptCbc()
    {
        var rc2 = RC2.Create();
        byte[] plaintext = new byte[16];
        byte[] iv = new byte[8];
        byte[] destination = new byte[24];
        int bytesWritten;
        rc2.TryEncryptCbc(plaintext, iv, destination, out bytesWritten, PaddingMode.PKCS7);
    }

    public void TestTryDecryptCbc()
    {
        var rc2 = RC2.Create();
        byte[] ciphertext = new byte[16];
        byte[] iv = new byte[8];
        byte[] destination = new byte[16];
        int bytesWritten;
        rc2.TryDecryptCbc(ciphertext, iv, destination, out bytesWritten, PaddingMode.PKCS7);
    }

    public void TestTryEncryptEcb()
    {
        var rc2 = RC2.Create();
        byte[] plaintext = new byte[16];
        byte[] destination = new byte[24];
        int bytesWritten;
        rc2.TryEncryptEcb(plaintext, destination, PaddingMode.None, out bytesWritten);
    }

    public void TestTryDecryptEcb()
    {
        var rc2 = RC2.Create();
        byte[] ciphertext = new byte[16];
        byte[] destination = new byte[16];
        int bytesWritten;
        rc2.TryDecryptEcb(ciphertext, destination, PaddingMode.None, out bytesWritten);
    }

    public void TestTryEncryptCfb()
    {
        var rc2 = RC2.Create();
        byte[] plaintext = new byte[16];
        byte[] iv = new byte[8];
        byte[] destination = new byte[24];
        int bytesWritten;
        rc2.TryEncryptCfb(plaintext, iv, destination, out bytesWritten, PaddingMode.None, 8);
    }

    public void TestTryDecryptCfb()
    {
        var rc2 = RC2.Create();
        byte[] ciphertext = new byte[16];
        byte[] iv = new byte[8];
        byte[] destination = new byte[16];
        int bytesWritten;
        rc2.TryDecryptCfb(ciphertext, iv, destination, out bytesWritten, PaddingMode.None, 8);
    }

    // -------------------------------------------------------------------------
    // Section 7: Key/IV generation
    // -------------------------------------------------------------------------

    public void TestGenerateKey()
    {
        var rc2 = RC2.Create();
        rc2.GenerateKey();
    }

    public void TestGenerateIV()
    {
        var rc2 = RC2.Create();
        rc2.GenerateIV();
    }

    // -------------------------------------------------------------------------
    // Section 8: Combined usage patterns (real-world scenarios)
    // Demonstrates that depending rules fire correctly for both derived classes.
    // -------------------------------------------------------------------------

    public void TestRc2CbcFullFlow()
    {
        var rc2 = RC2.Create();
        rc2.Mode = CipherMode.CBC;
        rc2.Padding = PaddingMode.PKCS7;
        var encryptor = rc2.CreateEncryptor();
    }

    public void TestRc2CspEncryptCbc()
    {
        var rc2 = new RC2CryptoServiceProvider();
        rc2.Mode = CipherMode.CBC;
        byte[] plaintext = new byte[16];
        byte[] iv = new byte[8];
        byte[] ciphertext = rc2.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);
    }

    public void TestRc2CspDecryptCbc()
    {
        var rc2 = new RC2CryptoServiceProvider();
        byte[] ciphertext = new byte[16];
        byte[] iv = new byte[8];
        byte[] plaintext = rc2.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
    }

    public void TestRc2CfbFeedback()
    {
        var rc2 = RC2.Create();
        rc2.Mode = CipherMode.CFB;
        rc2.FeedbackSize = 8;
        byte[] plaintext = new byte[16];
        byte[] iv = new byte[8];
        byte[] ciphertext = rc2.EncryptCfb(plaintext, iv, PaddingMode.None, 8);
    }

    public void TestRc2CbcWithEncryptorOverload()
    {
        var rc2 = RC2.Create();
        byte[] key = new byte[16];
        byte[] iv = new byte[8];
        var encryptor = rc2.CreateEncryptor(key, iv);
    }

    public void TestRc2EcbEncrypt()
    {
        var rc2 = new RC2CryptoServiceProvider();
        byte[] plaintext = new byte[16];
        byte[] ciphertext = rc2.EncryptEcb(plaintext, PaddingMode.None);
    }

    public void TestRc2CspEffectiveKeySize()
    {
        var rc2 = new RC2CryptoServiceProvider();
        rc2.EffectiveKeySize = 40;
    }
}
