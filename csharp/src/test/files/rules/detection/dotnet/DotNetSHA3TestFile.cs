using System.Security.Cryptography;
public class DotNetSHA3Test {
    public void TestSha3_256Create() { var h = SHA3_256.Create(); } // Noncompliant
    public void TestSha3_384Create() { var h = SHA3_384.Create(); } // Noncompliant
    public void TestSha3_512Create() { var h = SHA3_512.Create(); } // Noncompliant
    public void TestShake128()       { var h = new Shake128(); }    // Noncompliant
    public void TestShake256()       { var h = new Shake256(); }    // Noncompliant
}
