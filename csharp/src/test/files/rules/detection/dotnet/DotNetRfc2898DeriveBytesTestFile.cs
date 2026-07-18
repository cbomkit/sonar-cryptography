using System.Security.Cryptography;
public class DotNetRfc2898DeriveBytesTest {
    public void TestPbkdf2() {
        var kdf = new Rfc2898DeriveBytes("password", new byte[16], 10000, HashAlgorithmName.SHA256); // Noncompliant
    }
}
