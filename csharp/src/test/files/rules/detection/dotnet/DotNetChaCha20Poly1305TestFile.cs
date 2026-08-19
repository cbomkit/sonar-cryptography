using System.Security.Cryptography;

public class DotNetChaCha20Poly1305Test
{
    public void TestChaChaCreate()
    {
        var key = new byte [32];
        var chaCha = new ChaCha20Poly1305(key); // Noncompliant
    }

    public void TestChaChaEncrypt()
    {
        var key = new byte [32];
        var chaCha = new ChaCha20Poly1305(key); // Noncompliant

        var nonce = new byte[12];
        var plainText = new byte[32];
        var cipherText = new byte[32];
        var tag = new byte[16];
        var associatedData = new byte[32];

        chaCha.Encrypt(nonce, plainText, cipherText, tag, associatedData);
    }

    public void TestChaChaDecrypt()
    {
        var key = new byte [32];
        var chaCha = new ChaCha20Poly1305(key); // Noncompliant

        var nonce = new byte[12];
        var plainText = new byte[32];
        var cipherText = new byte[32];
        var tag = new byte[16];
        var associatedData = new byte[32];

        chaCha.Decrypt(nonce, plainText, cipherText, tag, associatedData);
    }

    public void TestChaChaEncryptReadOnlySpan()
    {
        var key = new byte [32];
        var chaCha = new ChaCha20Poly1305(key); // Noncompliant

        var nonce = new ReadOnlySpan<byte>[12];
        var plainText = new ReadOnlySpan<byte>[32];
        var cipherText = new ReadOnlySpan<byte>[32];
        var tag = new ReadOnlySpan<byte>[16];
        var associatedData = new ReadOnlySpan<byte>[32];

        chaCha.Encrypt(nonce, plainText, cipherText, tag, associatedData);
    }

    public void TestChaChaDecryptReadOnlySpan()
    {
        var key = new byte [32];
        var chaCha = new ChaCha20Poly1305(key); // Noncompliant

        var nonce = new ReadOnlySpan<byte>[12];
        var plainText = new ReadOnlySpan<byte>[32];
        var cipherText = new ReadOnlySpan<byte>[32];
        var tag = new ReadOnlySpan<byte>[16];
        var associatedData = new ReadOnlySpan<byte>[32];

        chaCha.Decrypt(nonce, cipherText, tag, plainText, associatedData);
    }
}
