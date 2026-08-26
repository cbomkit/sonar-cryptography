using System.Security.Cryptography;
public class DotNetRfc2898DeriveBytesTest {
    public void TestPbkdf2() {
        var kdf = new Rfc2898DeriveBytes("password", new byte[16], 10000, HashAlgorithmName.SHA256); // Noncompliant
    }

    public void TestPbkdf2GetBytes() {
        var kdf = new Rfc2898DeriveBytes("password", new byte[16], 10000, HashAlgorithmName.SHA256); // Noncompliant
        byte[] derived = kdf.GetBytes(32);
    }

    public void TestPbkdf2CryptDeriveKey() {
        var kdf = new Rfc2898DeriveBytes("password", new byte[16], 10000, HashAlgorithmName.SHA256); // Noncompliant
        byte[] iv = new byte[8];
        byte[] key = kdf.CryptDeriveKey("TripleDES", "SHA1", 192, iv);
    }

    public void TestPbkdf2StaticByteArray() {
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(
            new byte[8], new byte[16], 10000, HashAlgorithmName.SHA256, 32); // Noncompliant
    }

    public void TestPbkdf2StaticString() {
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(
            "password", new byte[16], 10000, HashAlgorithmName.SHA256, 32); // Noncompliant
    }
}
