/*
 * Comprehensive test file for System.Security.Cryptography DES detection rules.
 *
 * Covers both DES-related classes and their complete API surface:
 *   - DES (abstract base)
 *   - DESCryptoServiceProvider (derived from DES)
 *
 * Unlike Aes, DES has no CNG-backed subclass and no AEAD variant, so there are
 * fewer constructor scenarios in Section 1, and no AEAD sections.
 *
 * Architecture note: all methods inherited from SymmetricAlgorithm (EncryptCbc,
 * CreateEncryptor, etc.) are covered once here. The detection engine tracks the
 * variable and fires the same depending rules for every concrete DES subclass.
 */

using System.Security.Cryptography;

public class DotNetDESComprehensiveTest
{
    // -------------------------------------------------------------------------
    // Section 1: Factory methods / constructors
    // -------------------------------------------------------------------------

    public void TestDesCreate()
    {
        var des = DES.Create();
    }

    public void TestDesCreateNamed()
    {
        var des = DES.Create("DES");
    }

    public void TestDesCsp()
    {
        var des = new DESCryptoServiceProvider();
    }

    // -------------------------------------------------------------------------
    // Section 2: Property setters (via assignment → synthetic set_X invocations)
    // -------------------------------------------------------------------------

    public void TestPropertyModeCBC()
    {
        var des = DES.Create();
        des.Mode = CipherMode.CBC;
    }

    public void TestPropertyModeECB()
    {
        var des = DES.Create();
        des.Mode = CipherMode.ECB;
    }

    public void TestPropertyModeCFB()
    {
        var des = DES.Create();
        des.Mode = CipherMode.CFB;
    }

    public void TestPropertyModeOFB()
    {
        var des = DES.Create();
        des.Mode = CipherMode.OFB;
    }

    public void TestPropertyModeCTS()
    {
        var des = DES.Create();
        des.Mode = CipherMode.CTS;
    }

    public void TestPropertyKeySize()
    {
        var des = DES.Create();
        des.KeySize = 64;
    }

    public void TestPropertyPaddingPKCS7()
    {
        var des = DES.Create();
        des.Padding = PaddingMode.PKCS7;
    }

    public void TestPropertyPaddingNone()
    {
        var des = DES.Create();
        des.Padding = PaddingMode.None;
    }

    public void TestPropertyPaddingZeros()
    {
        var des = DES.Create();
        des.Padding = PaddingMode.Zeros;
    }

    public void TestPropertyPaddingANSIX923()
    {
        var des = DES.Create();
        des.Padding = PaddingMode.ANSIX923;
    }

    public void TestPropertyFeedbackSize()
    {
        var des = DES.Create();
        des.FeedbackSize = 8;
    }

    public void TestPropertyIV()
    {
        var des = DES.Create();
        des.IV = new byte[8];
    }

    public void TestPropertyKey()
    {
        var des = DES.Create();
        des.Key = new byte[8];
    }

    // -------------------------------------------------------------------------
    // Section 3: CreateEncryptor / CreateDecryptor
    // -------------------------------------------------------------------------

    public void TestCreateEncryptorNoArgs()
    {
        var des = DES.Create();
        var encryptor = des.CreateEncryptor();
    }

    public void TestCreateEncryptorWithArgs()
    {
        var des = DES.Create();
        byte[] key = new byte[8];
        byte[] iv = new byte[8];
        var encryptor = des.CreateEncryptor(key, iv);
    }

    public void TestCreateDecryptorNoArgs()
    {
        var des = DES.Create();
        var decryptor = des.CreateDecryptor();
    }

    public void TestCreateDecryptorWithArgs()
    {
        var des = DES.Create();
        byte[] key = new byte[8];
        byte[] iv = new byte[8];
        var decryptor = des.CreateDecryptor(key, iv);
    }

    // -------------------------------------------------------------------------
    // Section 4: Direct mode-specific encrypt methods
    // -------------------------------------------------------------------------

    public void TestEncryptCbc()
    {
        var des = DES.Create();
        byte[] plaintext = new byte[16];
        byte[] iv = new byte[8];
        byte[] ciphertext = des.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);
    }

    public void TestEncryptEcb()
    {
        var des = DES.Create();
        byte[] plaintext = new byte[16];
        byte[] ciphertext = des.EncryptEcb(plaintext, PaddingMode.None);
    }

    public void TestEncryptCfb()
    {
        var des = DES.Create();
        byte[] plaintext = new byte[16];
        byte[] iv = new byte[8];
        byte[] ciphertext = des.EncryptCfb(plaintext, iv, PaddingMode.None, 8);
    }

    // -------------------------------------------------------------------------
    // Section 5: Direct mode-specific decrypt methods
    // -------------------------------------------------------------------------

    public void TestDecryptCbc()
    {
        var des = DES.Create();
        byte[] ciphertext = new byte[16];
        byte[] iv = new byte[8];
        byte[] plaintext = des.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
    }

    public void TestDecryptEcb()
    {
        var des = DES.Create();
        byte[] ciphertext = new byte[16];
        byte[] plaintext = des.DecryptEcb(ciphertext, PaddingMode.None);
    }

    public void TestDecryptCfb()
    {
        var des = DES.Create();
        byte[] ciphertext = new byte[16];
        byte[] iv = new byte[8];
        byte[] plaintext = des.DecryptCfb(ciphertext, iv, PaddingMode.None, 8);
    }

    // -------------------------------------------------------------------------
    // Section 6: Try* variants
    // -------------------------------------------------------------------------

    public void TestTryEncryptCbc()
    {
        var des = DES.Create();
        byte[] plaintext = new byte[16];
        byte[] iv = new byte[8];
        byte[] destination = new byte[24];
        int bytesWritten;
        des.TryEncryptCbc(plaintext, iv, destination, out bytesWritten, PaddingMode.PKCS7);
    }

    public void TestTryDecryptCbc()
    {
        var des = DES.Create();
        byte[] ciphertext = new byte[16];
        byte[] iv = new byte[8];
        byte[] destination = new byte[16];
        int bytesWritten;
        des.TryDecryptCbc(ciphertext, iv, destination, out bytesWritten, PaddingMode.PKCS7);
    }

    public void TestTryEncryptEcb()
    {
        var des = DES.Create();
        byte[] plaintext = new byte[16];
        byte[] destination = new byte[24];
        int bytesWritten;
        des.TryEncryptEcb(plaintext, destination, PaddingMode.None, out bytesWritten);
    }

    public void TestTryDecryptEcb()
    {
        var des = DES.Create();
        byte[] ciphertext = new byte[16];
        byte[] destination = new byte[16];
        int bytesWritten;
        des.TryDecryptEcb(ciphertext, destination, PaddingMode.None, out bytesWritten);
    }

    public void TestTryEncryptCfb()
    {
        var des = DES.Create();
        byte[] plaintext = new byte[16];
        byte[] iv = new byte[8];
        byte[] destination = new byte[24];
        int bytesWritten;
        des.TryEncryptCfb(plaintext, iv, destination, out bytesWritten, PaddingMode.None, 8);
    }

    public void TestTryDecryptCfb()
    {
        var des = DES.Create();
        byte[] ciphertext = new byte[16];
        byte[] iv = new byte[8];
        byte[] destination = new byte[16];
        int bytesWritten;
        des.TryDecryptCfb(ciphertext, iv, destination, out bytesWritten, PaddingMode.None, 8);
    }

    // -------------------------------------------------------------------------
    // Section 7: Key/IV generation
    // -------------------------------------------------------------------------

    public void TestGenerateKey()
    {
        var des = DES.Create();
        des.GenerateKey();
    }

    public void TestGenerateIV()
    {
        var des = DES.Create();
        des.GenerateIV();
    }

    // -------------------------------------------------------------------------
    // Section 8: Combined usage patterns (real-world scenarios)
    // Demonstrates that depending rules fire correctly for both derived classes.
    // -------------------------------------------------------------------------

    public void TestDesCbcFullFlow()
    {
        var des = DES.Create();
        des.Mode = CipherMode.CBC;
        des.Padding = PaddingMode.PKCS7;
        var encryptor = des.CreateEncryptor();
    }

    public void TestDesCspEncryptCbc()
    {
        var des = new DESCryptoServiceProvider();
        des.Mode = CipherMode.CBC;
        byte[] plaintext = new byte[16];
        byte[] iv = new byte[8];
        byte[] ciphertext = des.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);
    }

    public void TestDesCspDecryptCbc()
    {
        var des = new DESCryptoServiceProvider();
        byte[] ciphertext = new byte[16];
        byte[] iv = new byte[8];
        byte[] plaintext = des.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
    }

    public void TestDesCfbFeedback()
    {
        var des = DES.Create();
        des.Mode = CipherMode.CFB;
        des.FeedbackSize = 8;
        byte[] plaintext = new byte[16];
        byte[] iv = new byte[8];
        byte[] ciphertext = des.EncryptCfb(plaintext, iv, PaddingMode.None, 8);
    }

    public void TestDesCbcWithEncryptorOverload()
    {
        var des = DES.Create();
        byte[] key = new byte[8];
        byte[] iv = new byte[8];
        var encryptor = des.CreateEncryptor(key, iv);
    }

    public void TestDesEcbEncrypt()
    {
        var des = new DESCryptoServiceProvider();
        byte[] plaintext = new byte[16];
        byte[] ciphertext = des.EncryptEcb(plaintext, PaddingMode.None);
    }
}
