/*
 * Comprehensive test file for System.Security.Cryptography.ChaCha20Poly1305 detection rules.
 *
 * Covers the full API surface of the ChaCha20Poly1305 AEAD class:
 *   - constructor overloads (byte[] key, ReadOnlySpan<byte> key)
 *   - Encrypt overloads (byte[] and ReadOnlySpan<byte>), with and without associatedData
 *   - Decrypt overloads (byte[] and ReadOnlySpan<byte>), with and without associatedData
 *   - combined / round-trip usage patterns
 *
 * Architecture note: Encrypt/Decrypt are depending rules attached to the constructor
 * (see DotNetChaCha20Poly1305.java, mirroring AesGcm/AesCcm in DotNetAES.java), so each
 * method below that constructs-then-uses the object produces a single finding with nested
 * Encrypt/Decrypt children, not separate disconnected findings.
 */

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
        var key = new ReadOnlySpan<byte>[32];
        var chaCha = new ChaCha20Poly1305(key);
    }

    // -------------------------------------------------------------------------
    // Section 2: Encrypt — byte[] overload
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
    // Section 3: Encrypt — ReadOnlySpan<byte> overload
    // -------------------------------------------------------------------------

    public void TestEncryptSpanWithAad()
    {
        var key = new byte[32];
        var chaCha = new ChaCha20Poly1305(key);

        var nonce = new ReadOnlySpan<byte>[12];
        var plainText = new ReadOnlySpan<byte>[32];
        var cipherText = new ReadOnlySpan<byte>[32];
        var tag = new ReadOnlySpan<byte>[16];
        var associatedData = new ReadOnlySpan<byte>[32];

        chaCha.Encrypt(nonce, plainText, cipherText, tag, associatedData);
    }

    public void TestEncryptSpanNoAad()
    {
        var key = new byte[32];
        var chaCha = new ChaCha20Poly1305(key);

        var nonce = new ReadOnlySpan<byte>[12];
        var plainText = new ReadOnlySpan<byte>[32];
        var cipherText = new ReadOnlySpan<byte>[32];
        var tag = new ReadOnlySpan<byte>[16];

        chaCha.Encrypt(nonce, plainText, cipherText, tag);
    }

    // -------------------------------------------------------------------------
    // Section 4: Decrypt — byte[] overload
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
    // Section 5: Decrypt — ReadOnlySpan<byte> overload
    // -------------------------------------------------------------------------

    public void TestDecryptSpanWithAad()
    {
        var key = new byte[32];
        var chaCha = new ChaCha20Poly1305(key);

        var nonce = new ReadOnlySpan<byte>[12];
        var cipherText = new ReadOnlySpan<byte>[32];
        var tag = new ReadOnlySpan<byte>[16];
        var plainText = new ReadOnlySpan<byte>[32];
        var associatedData = new ReadOnlySpan<byte>[32];

        chaCha.Decrypt(nonce, cipherText, tag, plainText, associatedData);
    }

    public void TestDecryptSpanNoAad()
    {
        var key = new byte[32];
        var chaCha = new ChaCha20Poly1305(key);

        var nonce = new ReadOnlySpan<byte>[12];
        var cipherText = new ReadOnlySpan<byte>[32];
        var tag = new ReadOnlySpan<byte>[16];
        var plainText = new ReadOnlySpan<byte>[32];

        chaCha.Decrypt(nonce, cipherText, tag, plainText);
    }
}
