/*
 * Test file for System.Security.Cryptography.ChaCha20Poly1305 detection rules.
 *
 * Covers the full API surface of the ChaCha20Poly1305 class:
 *   - constructor overloads (byte[] key, ReadOnlySpan<byte> key)
 *   - Encrypt overloads (byte[] and ReadOnlySpan<byte>), with and without associatedData
 *   - Decrypt overloads (byte[] and ReadOnlySpan<byte>), with and without associatedData
 *
 * Since the constructor accepts either a byte[] key or a ReadOnlySpan<byte> key, and
 * Encrypt/Decrypt each accept either byte[] or ReadOnlySpan<byte> buffers, there are
 * 4 key-type/buffer-type combinations for Encrypt and 4 for Decrypt. Sections 2-5 pair
 * a byte[] key with both buffer overloads; Sections 6-9 pair a ReadOnlySpan<byte> key
 * with both buffer overloads.
 *
 * Architecture note: Encrypt/Decrypt are depending rules attached to the constructor
 * (see DotNetChaCha20Poly1305.java), so each method below that constructs-then-uses
 * the object produces a single finding with nested Encrypt/Decrypt children, not separate
 * disconnected findings.
 */

using System;
using System.Security.Cryptography;

public class DotNetChaCha20Poly1305ComprehensiveTest
{
    // -------------------------------------------------------------------------
    // Section 1: Constructor overloads
    // -------------------------------------------------------------------------

    public void TestConstructByteArrayKey()
    {
        var key = new byte[32];
        var chaCha = new ChaCha20Poly1305(key);
    }

    public void TestConstructSpanKey()
    {
        Span<byte> key = stackalloc byte[32];
        var chaCha = new ChaCha20Poly1305(key);
    }

    // -------------------------------------------------------------------------
    // Section 2: byte[] key + Encrypt — byte[] overload
    // -------------------------------------------------------------------------

    public void TestEncryptByteArrayWithAad()
    {
        var key = new byte[32];
        var chaCha = new ChaCha20Poly1305(key);

        var nonce = new byte[12];
        var plainText = new byte[32];
        var cipherText = new byte[32];
        var tag = new byte[16];
        var associatedData = new byte[32];

        chaCha.Encrypt(nonce, plainText, cipherText, tag, associatedData);
    }

    public void TestEncryptByteArrayNoAad()
    {
        var key = new byte[32];
        var chaCha = new ChaCha20Poly1305(key);

        var nonce = new byte[12];
        var plainText = new byte[32];
        var cipherText = new byte[32];
        var tag = new byte[16];

        chaCha.Encrypt(nonce, plainText, cipherText, tag);
    }

    // -------------------------------------------------------------------------
    // Section 3: byte[] key + Encrypt — ReadOnlySpan<byte> overload
    // -------------------------------------------------------------------------

    public void TestEncryptSpanWithAad()
    {
        var key = new byte[32];
        var chaCha = new ChaCha20Poly1305(key);

        Span<byte> nonce = stackalloc byte[12];
        Span<byte> plainText = stackalloc byte[32];
        Span<byte> cipherText = stackalloc byte[32];
        Span<byte> tag = stackalloc byte[16];
        Span<byte> associatedData = stackalloc byte[32];

        chaCha.Encrypt(nonce, plainText, cipherText, tag, associatedData);
    }

    public void TestEncryptSpanNoAad()
    {
        var key = new byte[32];
        var chaCha = new ChaCha20Poly1305(key);

        Span<byte> nonce = stackalloc byte[12];
        Span<byte> plainText = stackalloc byte[32];
        Span<byte> cipherText = stackalloc byte[32];
        Span<byte> tag = stackalloc byte[16];

        chaCha.Encrypt(nonce, plainText, cipherText, tag);
    }

    // -------------------------------------------------------------------------
    // Section 4: byte[] key + Decrypt — byte[] overload
    // -------------------------------------------------------------------------

    public void TestDecryptByteArrayWithAad()
    {
        var key = new byte[32];
        var chaCha = new ChaCha20Poly1305(key);

        var nonce = new byte[12];
        var cipherText = new byte[32];
        var tag = new byte[16];
        var plainText = new byte[32];
        var associatedData = new byte[32];

        chaCha.Decrypt(nonce, cipherText, tag, plainText, associatedData);
    }

    public void TestDecryptByteArrayNoAad()
    {
        var key = new byte[32];
        var chaCha = new ChaCha20Poly1305(key);

        var nonce = new byte[12];
        var cipherText = new byte[32];
        var tag = new byte[16];
        var plainText = new byte[32];

        chaCha.Decrypt(nonce, cipherText, tag, plainText);
    }

    // -------------------------------------------------------------------------
    // Section 5: byte[] key + Decrypt — ReadOnlySpan<byte> overload
    // -------------------------------------------------------------------------

    public void TestDecryptSpanWithAad()
    {
        var key = new byte[32];
        var chaCha = new ChaCha20Poly1305(key);

        Span<byte> nonce = stackalloc byte[12];
        Span<byte> cipherText = stackalloc byte[32];
        Span<byte> tag = stackalloc byte[16];
        Span<byte> plainText = stackalloc byte[32];
        Span<byte> associatedData = stackalloc byte[32];

        chaCha.Decrypt(nonce, cipherText, tag, plainText, associatedData);
    }

    public void TestDecryptSpanNoAad()
    {
        var key = new byte[32];
        var chaCha = new ChaCha20Poly1305(key);

        Span<byte> nonce = stackalloc byte[12];
        Span<byte> cipherText = stackalloc byte[32];
        Span<byte> tag = stackalloc byte[16];
        Span<byte> plainText = stackalloc byte[32];

        chaCha.Decrypt(nonce, cipherText, tag, plainText);
    }

    // -------------------------------------------------------------------------
    // Section 6: ReadOnlySpan<byte> key + Encrypt — byte[] overload
    // -------------------------------------------------------------------------

    public void TestSpanKeyEncryptByteArrayWithAad()
    {
        Span<byte> key = stackalloc byte[32];
        var chaCha = new ChaCha20Poly1305(key);

        var nonce = new byte[12];
        var plainText = new byte[32];
        var cipherText = new byte[32];
        var tag = new byte[16];
        var associatedData = new byte[32];

        chaCha.Encrypt(nonce, plainText, cipherText, tag, associatedData);
    }

    public void TestSpanKeyEncryptByteArrayNoAad()
    {
        Span<byte> key = stackalloc byte[32];
        var chaCha = new ChaCha20Poly1305(key);

        var nonce = new byte[12];
        var plainText = new byte[32];
        var cipherText = new byte[32];
        var tag = new byte[16];

        chaCha.Encrypt(nonce, plainText, cipherText, tag);
    }

    // -------------------------------------------------------------------------
    // Section 7: ReadOnlySpan<byte> key + Encrypt — ReadOnlySpan<byte> overload
    // -------------------------------------------------------------------------

    public void TestSpanKeyEncryptSpanWithAad()
    {
        Span<byte> key = stackalloc byte[32];
        var chaCha = new ChaCha20Poly1305(key);

        Span<byte> nonce = stackalloc byte[12];
        Span<byte> plainText = stackalloc byte[32];
        Span<byte> cipherText = stackalloc byte[32];
        Span<byte> tag = stackalloc byte[16];
        Span<byte> associatedData = stackalloc byte[32];

        chaCha.Encrypt(nonce, plainText, cipherText, tag, associatedData);
    }

    public void TestSpanKeyEncryptSpanNoAad()
    {
        Span<byte> key = stackalloc byte[32];
        var chaCha = new ChaCha20Poly1305(key);

        Span<byte> nonce = stackalloc byte[12];
        Span<byte> plainText = stackalloc byte[32];
        Span<byte> cipherText = stackalloc byte[32];
        Span<byte> tag = stackalloc byte[16];

        chaCha.Encrypt(nonce, plainText, cipherText, tag);
    }

    // -------------------------------------------------------------------------
    // Section 8: ReadOnlySpan<byte> key + Decrypt — byte[] overload
    // -------------------------------------------------------------------------

    public void TestSpanKeyDecryptByteArrayWithAad()
    {
        Span<byte> key = stackalloc byte[32];
        var chaCha = new ChaCha20Poly1305(key);

        var nonce = new byte[12];
        var cipherText = new byte[32];
        var tag = new byte[16];
        var plainText = new byte[32];
        var associatedData = new byte[32];

        chaCha.Decrypt(nonce, cipherText, tag, plainText, associatedData);
    }

    public void TestSpanKeyDecryptByteArrayNoAad()
    {
        Span<byte> key = stackalloc byte[32];
        var chaCha = new ChaCha20Poly1305(key);

        var nonce = new byte[12];
        var cipherText = new byte[32];
        var tag = new byte[16];
        var plainText = new byte[32];

        chaCha.Decrypt(nonce, cipherText, tag, plainText);
    }

    // -------------------------------------------------------------------------
    // Section 9: ReadOnlySpan<byte> key + Decrypt — ReadOnlySpan<byte> overload
    // -------------------------------------------------------------------------

    public void TestSpanKeyDecryptSpanWithAad()
    {
        Span<byte> key = stackalloc byte[32];
        var chaCha = new ChaCha20Poly1305(key);

        Span<byte> nonce = stackalloc byte[12];
        Span<byte> cipherText = stackalloc byte[32];
        Span<byte> tag = stackalloc byte[16];
        Span<byte> plainText = stackalloc byte[32];
        Span<byte> associatedData = stackalloc byte[32];

        chaCha.Decrypt(nonce, cipherText, tag, plainText, associatedData);
    }

    public void TestSpanKeyDecryptSpanNoAad()
    {
        Span<byte> key = stackalloc byte[32];
        var chaCha = new ChaCha20Poly1305(key);

        Span<byte> nonce = stackalloc byte[12];
        Span<byte> cipherText = stackalloc byte[32];
        Span<byte> tag = stackalloc byte[16];
        Span<byte> plainText = stackalloc byte[32];

        chaCha.Decrypt(nonce, cipherText, tag, plainText);
    }
}
