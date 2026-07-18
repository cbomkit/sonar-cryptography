using System.Security.Cryptography;
public class DotNetHMACTest {
    public void TestHmacSha1()   { var h = new HMACSHA1(); }   // Noncompliant
    public void TestHmacSha256() { var h = new HMACSHA256(); } // Noncompliant
    public void TestHmacSha384() { var h = new HMACSHA384(); } // Noncompliant
    public void TestHmacSha512() { var h = new HMACSHA512(); } // Noncompliant
    public void TestHmacMd5()    { var h = new HMACMD5(); }    // Noncompliant
}
