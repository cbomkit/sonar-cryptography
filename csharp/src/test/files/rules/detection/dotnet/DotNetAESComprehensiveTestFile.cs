/*
 * Comprehensive test file for System.Security.Cryptography AES detection rules.
 *
 * Covers all five AES-related classes and their complete API surface:
 *   - Aes (abstract base)
 *   - AesManaged, AesCng, AesCryptoServiceProvider (derived from Aes)
 *   - AesGcm, AesCcm (AEAD, separate class hierarchy, same namespace)
 *
 * Architecture note: all methods inherited from SymmetricAlgorithm (EncryptCbc,
 * CreateEncryptor, etc.) are covered once here. The detection engine tracks the
 * variable and fires the same depending rules for every concrete Aes subclass.
 */

using System.Security.Cryptography;

public class DotNetAESComprehensiveTest
{
    // -------------------------------------------------------------------------
    // Section 1: Factory methods / constructors
    // -------------------------------------------------------------------------

    public void TestAesCreate()
    {
        var aes = Aes.Create();
    }

    public void TestAesCreateNamed()
    {
        var aes = Aes.Create("AES");
    }

    public void TestAesManaged()
    {
        var aes = new AesManaged();
    }

    public void TestAesCng()
    {
        var aes = new AesCng();
    }

    public void TestAesCngNamed()
    {
        var aes = new AesCng("myKey");
    }

    public void TestAesCsp()
    {
        var aes = new AesCryptoServiceProvider();
    }

    public void TestAesGcm()
    {
        byte[] key = new byte[32];
        var aesGcm = new AesGcm(key);
    }

    public void TestAesCcm()
    {
        byte[] key = new byte[32];
        var aesCcm = new AesCcm(key);
    }

    // -------------------------------------------------------------------------
    // Section 2: Property setters (via assignment → synthetic set_X invocations)
    // -------------------------------------------------------------------------

    public void TestPropertyModeCBC()
    {
        var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
    }

    public void TestPropertyModeECB()
    {
        var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
    }

    public void TestPropertyModeCFB()
    {
        var aes = Aes.Create();
        aes.Mode = CipherMode.CFB;
    }

    public void TestPropertyModeOFB()
    {
        var aes = Aes.Create();
        aes.Mode = CipherMode.OFB;
    }

    public void TestPropertyModeCTS()
    {
        var aes = Aes.Create();
        aes.Mode = CipherMode.CTS;
    }

    public void TestPropertyKeySize128()
    {
        var aes = Aes.Create();
        aes.KeySize = 128;
    }

    public void TestPropertyKeySize192()
    {
        var aes = Aes.Create();
        aes.KeySize = 192;
    }

    public void TestPropertyKeySize256()
    {
        var aes = Aes.Create();
        aes.KeySize = 256;
    }

    public void TestPropertyPaddingPKCS7()
    {
        var aes = Aes.Create();
        aes.Padding = PaddingMode.PKCS7;
    }

    public void TestPropertyPaddingNone()
    {
        var aes = Aes.Create();
        aes.Padding = PaddingMode.None;
    }

    public void TestPropertyPaddingZeros()
    {
        var aes = Aes.Create();
        aes.Padding = PaddingMode.Zeros;
    }

    public void TestPropertyPaddingANSIX923()
    {
        var aes = Aes.Create();
        aes.Padding = PaddingMode.ANSIX923;
    }

    public void TestPropertyFeedbackSize()
    {
        var aes = Aes.Create();
        aes.FeedbackSize = 128;
    }

    public void TestPropertyIV()
    {
        var aes = Aes.Create();
        aes.IV = new byte[16];
    }

    public void TestPropertyKey()
    {
        var aes = Aes.Create();
        aes.Key = new byte[32];
    }

    // -------------------------------------------------------------------------
    // Section 3: CreateEncryptor / CreateDecryptor
    // -------------------------------------------------------------------------

    public void TestCreateEncryptorNoArgs()
    {
        var aes = Aes.Create();
        var encryptor = aes.CreateEncryptor();
    }

    public void TestCreateEncryptorWithArgs()
    {
        var aes = Aes.Create();
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        var encryptor = aes.CreateEncryptor(key, iv);
    }

    public void TestCreateDecryptorNoArgs()
    {
        var aes = Aes.Create();
        var decryptor = aes.CreateDecryptor();
    }

    public void TestCreateDecryptorWithArgs()
    {
        var aes = Aes.Create();
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        var decryptor = aes.CreateDecryptor(key, iv);
    }

    // -------------------------------------------------------------------------
    // Section 4: Direct mode-specific encrypt methods
    // -------------------------------------------------------------------------

    public void TestEncryptCbc()
    {
        var aes = Aes.Create();
        byte[] plaintext = new byte[32];
        byte[] iv = new byte[16];
        byte[] ciphertext = aes.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);
    }

    public void TestEncryptEcb()
    {
        var aes = Aes.Create();
        byte[] plaintext = new byte[32];
        byte[] ciphertext = aes.EncryptEcb(plaintext, PaddingMode.None);
    }

    public void TestEncryptCfb()
    {
        var aes = Aes.Create();
        byte[] plaintext = new byte[32];
        byte[] iv = new byte[16];
        byte[] ciphertext = aes.EncryptCfb(plaintext, iv, PaddingMode.None, 128);
    }

    // -------------------------------------------------------------------------
    // Section 5: Direct mode-specific decrypt methods
    // -------------------------------------------------------------------------

    public void TestDecryptCbc()
    {
        var aes = Aes.Create();
        byte[] ciphertext = new byte[32];
        byte[] iv = new byte[16];
        byte[] plaintext = aes.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
    }

    public void TestDecryptEcb()
    {
        var aes = Aes.Create();
        byte[] ciphertext = new byte[32];
        byte[] plaintext = aes.DecryptEcb(ciphertext, PaddingMode.None);
    }

    public void TestDecryptCfb()
    {
        var aes = Aes.Create();
        byte[] ciphertext = new byte[32];
        byte[] iv = new byte[16];
        byte[] plaintext = aes.DecryptCfb(ciphertext, iv, PaddingMode.None, 128);
    }

    // -------------------------------------------------------------------------
    // Section 6: Try* variants
    // -------------------------------------------------------------------------

    public void TestTryEncryptCbc()
    {
        var aes = Aes.Create();
        byte[] plaintext = new byte[32];
        byte[] iv = new byte[16];
        byte[] destination = new byte[48];
        int bytesWritten;
        aes.TryEncryptCbc(plaintext, iv, destination, out bytesWritten, PaddingMode.PKCS7);
    }

    public void TestTryDecryptCbc()
    {
        var aes = Aes.Create();
        byte[] ciphertext = new byte[32];
        byte[] iv = new byte[16];
        byte[] destination = new byte[32];
        int bytesWritten;
        aes.TryDecryptCbc(ciphertext, iv, destination, out bytesWritten, PaddingMode.PKCS7);
    }

    public void TestTryEncryptEcb()
    {
        var aes = Aes.Create();
        byte[] plaintext = new byte[32];
        byte[] destination = new byte[48];
        int bytesWritten;
        aes.TryEncryptEcb(plaintext, destination, PaddingMode.None, out bytesWritten);
    }

    public void TestTryDecryptEcb()
    {
        var aes = Aes.Create();
        byte[] ciphertext = new byte[32];
        byte[] destination = new byte[32];
        int bytesWritten;
        aes.TryDecryptEcb(ciphertext, destination, PaddingMode.None, out bytesWritten);
    }

    public void TestTryEncryptCfb()
    {
        var aes = Aes.Create();
        byte[] plaintext = new byte[32];
        byte[] iv = new byte[16];
        byte[] destination = new byte[48];
        int bytesWritten;
        aes.TryEncryptCfb(plaintext, iv, destination, out bytesWritten, PaddingMode.None, 128);
    }

    public void TestTryDecryptCfb()
    {
        var aes = Aes.Create();
        byte[] ciphertext = new byte[32];
        byte[] iv = new byte[16];
        byte[] destination = new byte[32];
        int bytesWritten;
        aes.TryDecryptCfb(ciphertext, iv, destination, out bytesWritten, PaddingMode.None, 128);
    }

    // -------------------------------------------------------------------------
    // Section 7: Key/IV generation
    // -------------------------------------------------------------------------

    public void TestGenerateKey()
    {
        var aes = Aes.Create();
        aes.GenerateKey();
    }

    public void TestGenerateIV()
    {
        var aes = Aes.Create();
        aes.GenerateIV();
    }

    // -------------------------------------------------------------------------
    // Section 8: AesGcm AEAD operations
    // -------------------------------------------------------------------------

    public void TestAesGcmEncrypt()
    {
        byte[] key = new byte[32];
        var aesGcm = new AesGcm(key);
        byte[] nonce = new byte[12];
        byte[] plaintext = new byte[32];
        byte[] ciphertext = new byte[32];
        byte[] tag = new byte[16];
        byte[] aad = new byte[8];
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
    }

    public void TestAesGcmDecrypt()
    {
        byte[] key = new byte[32];
        var aesGcm = new AesGcm(key);
        byte[] nonce = new byte[12];
        byte[] ciphertext = new byte[32];
        byte[] tag = new byte[16];
        byte[] plaintext = new byte[32];
        byte[] aad = new byte[8];
        aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, aad);
    }

    // -------------------------------------------------------------------------
    // Section 9: AesCcm AEAD operations
    // -------------------------------------------------------------------------

    public void TestAesCcmEncrypt()
    {
        byte[] key = new byte[32];
        var aesCcm = new AesCcm(key);
        byte[] nonce = new byte[12];
        byte[] plaintext = new byte[32];
        byte[] ciphertext = new byte[32];
        byte[] tag = new byte[16];
        byte[] aad = new byte[8];
        aesCcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
    }

    public void TestAesCcmDecrypt()
    {
        byte[] key = new byte[32];
        var aesCcm = new AesCcm(key);
        byte[] nonce = new byte[12];
        byte[] ciphertext = new byte[32];
        byte[] tag = new byte[16];
        byte[] plaintext = new byte[32];
        byte[] aad = new byte[8];
        aesCcm.Decrypt(nonce, ciphertext, tag, plaintext, aad);
    }

    // -------------------------------------------------------------------------
    // Section 10: Combined usage patterns (real-world scenarios)
    // Demonstrates that depending rules fire correctly for ALL derived classes.
    // -------------------------------------------------------------------------

    public void TestAesCbcFullFlow()
    {
        var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.KeySize = 256;
        aes.Padding = PaddingMode.PKCS7;
        var encryptor = aes.CreateEncryptor();
    }

    public void TestAesCngEncryptCbc()
    {
        var aes = new AesCng();
        aes.Mode = CipherMode.CBC;
        byte[] plaintext = new byte[32];
        byte[] iv = new byte[16];
        byte[] ciphertext = aes.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);
    }

    public void TestAesCspDecryptCbc()
    {
        var aes = new AesCryptoServiceProvider();
        byte[] ciphertext = new byte[32];
        byte[] iv = new byte[16];
        byte[] plaintext = aes.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
    }

    public void TestAesManagedCfbFeedback()
    {
        var aes = new AesManaged();
        aes.Mode = CipherMode.CFB;
        aes.FeedbackSize = 128;
        byte[] plaintext = new byte[32];
        byte[] iv = new byte[16];
        byte[] ciphertext = aes.EncryptCfb(plaintext, iv, PaddingMode.None, 128);
    }

    public void TestAesCbcWithEncryptorOverload()
    {
        var aes = Aes.Create();
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        var encryptor = aes.CreateEncryptor(key, iv);
    }

    public void TestAesEcbEncrypt()
    {
        var aes = new AesCng();
        byte[] plaintext = new byte[32];
        byte[] ciphertext = aes.EncryptEcb(plaintext, PaddingMode.None);
    }

    public void TestAesGcmFullFlow()
    {
        byte[] key = new byte[32];
        var aesGcm = new AesGcm(key);
        byte[] nonce = new byte[12];
        byte[] plaintext = new byte[32];
        byte[] ciphertext = new byte[32];
        byte[] tag = new byte[16];
        byte[] aad = new byte[8];
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
    }

    public void TestAesCcmFullFlow()
    {
        byte[] key = new byte[32];
        var aesCcm = new AesCcm(key);
        byte[] nonce = new byte[12];
        byte[] plaintext = new byte[32];
        byte[] ciphertext = new byte[32];
        byte[] tag = new byte[16];
        byte[] aad = new byte[8];
        aesCcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
    }
}
