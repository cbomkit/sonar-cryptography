/*
 * Test file for System.Security.Cryptography ChaCha20Poly1305 detection rules.
 *
 * ChaCha20Poly1305 is a sealed AEAD cipher class, structurally analogous to AesGcm/AesCcm:
 * constructed from a key, with Encrypt/Decrypt methods taking nonce, plaintext/ciphertext,
 * tag and an optional associated-data buffer.
 */

using System.Security.Cryptography;

public class DotNetChaCha20Poly1305Test
{
    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    public void TestChaCha20Poly1305Ctor()
    {
        byte[] key = new byte[32];
        var chaCha20Poly1305 = new ChaCha20Poly1305(key);
    }

    // -------------------------------------------------------------------------
    // Encrypt (with and without the optional associated-data argument)
    // -------------------------------------------------------------------------

    public void TestChaCha20Poly1305Encrypt()
    {
        byte[] key = new byte[32];
        var chaCha20Poly1305 = new ChaCha20Poly1305(key);
        byte[] nonce = new byte[12];
        byte[] plaintext = new byte[32];
        byte[] ciphertext = new byte[32];
        byte[] tag = new byte[16];
        byte[] associatedData = new byte[8];
        chaCha20Poly1305.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
    }

    public void TestChaCha20Poly1305EncryptNoAad()
    {
        byte[] key = new byte[32];
        var chaCha20Poly1305 = new ChaCha20Poly1305(key);
        byte[] nonce = new byte[12];
        byte[] plaintext = new byte[32];
        byte[] ciphertext = new byte[32];
        byte[] tag = new byte[16];
        chaCha20Poly1305.Encrypt(nonce, plaintext, ciphertext, tag);
    }

    // -------------------------------------------------------------------------
    // Decrypt (with and without the optional associated-data argument)
    // -------------------------------------------------------------------------

    public void TestChaCha20Poly1305Decrypt()
    {
        byte[] key = new byte[32];
        var chaCha20Poly1305 = new ChaCha20Poly1305(key);
        byte[] nonce = new byte[12];
        byte[] ciphertext = new byte[32];
        byte[] tag = new byte[16];
        byte[] plaintext = new byte[32];
        byte[] associatedData = new byte[8];
        chaCha20Poly1305.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
    }

    public void TestChaCha20Poly1305DecryptNoAad()
    {
        byte[] key = new byte[32];
        var chaCha20Poly1305 = new ChaCha20Poly1305(key);
        byte[] nonce = new byte[12];
        byte[] ciphertext = new byte[32];
        byte[] tag = new byte[16];
        byte[] plaintext = new byte[32];
        chaCha20Poly1305.Decrypt(nonce, ciphertext, tag, plaintext);
    }

    // -------------------------------------------------------------------------
    // Combined usage pattern (real-world scenario)
    // -------------------------------------------------------------------------

    public void TestChaCha20Poly1305FullFlow()
    {
        byte[] key = new byte[32];
        var chaCha20Poly1305 = new ChaCha20Poly1305(key);
        byte[] nonce = new byte[12];
        byte[] plaintext = new byte[32];
        byte[] ciphertext = new byte[32];
        byte[] tag = new byte[16];
        byte[] associatedData = new byte[8];
        chaCha20Poly1305.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
    }
}
