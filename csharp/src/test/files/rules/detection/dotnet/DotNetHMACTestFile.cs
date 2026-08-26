using System.Security.Cryptography;
public class DotNetHMACTest {
    public void TestHmacSha1()   { var h = new HMACSHA1(); }   // Noncompliant
    public void TestHmacSha256() { var h = new HMACSHA256(); } // Noncompliant
    public void TestHmacSha384() { var h = new HMACSHA384(); } // Noncompliant
    public void TestHmacSha512() { var h = new HMACSHA512(); } // Noncompliant
    public void TestHmacMd5()    { var h = new HMACMD5(); }    // Noncompliant
    public void TestHmacRipemd160() { var h = new HMACRIPEMD160(); } // Noncompliant
    public void TestHmacSha3_256()  { var h = new HMACSHA3_256(); }  // Noncompliant
    public void TestHmacSha3_384()  { var h = new HMACSHA3_384(); }  // Noncompliant
    public void TestHmacSha3_512()  { var h = new HMACSHA3_512(); }  // Noncompliant
    public void TestMacTripleDes()  { var h = new MACTripleDES(); }  // Noncompliant
}
