using System.Security.Cryptography;
public class DotNetSHATest {
    public void TestSha1Create()   { var h = SHA1.Create(); }   // Noncompliant
    public void TestSha256Create() { var h = SHA256.Create(); } // Noncompliant
    public void TestSha384Create() { var h = SHA384.Create(); } // Noncompliant
    public void TestSha512Create() { var h = SHA512.Create(); } // Noncompliant
    public void TestMd5Create()    { var h = MD5.Create(); }    // Noncompliant
}
