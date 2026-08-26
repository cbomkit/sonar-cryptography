using System.Security.Cryptography;
public class DotNetSHATest {
    public void TestSha1Create()   { var h = SHA1.Create(); }   // Noncompliant
    public void TestSha256Create() { var h = SHA256.Create(); } // Noncompliant
    public void TestSha384Create() { var h = SHA384.Create(); } // Noncompliant
    public void TestSha512Create() { var h = SHA512.Create(); } // Noncompliant
    public void TestMd5Create()    { var h = MD5.Create(); }    // Noncompliant

    public void TestMd5CreateNamed()    { var h = MD5.Create("MD5"); }       // Noncompliant
    public void TestSha1CreateNamed()   { var h = SHA1.Create("SHA1"); }     // Noncompliant
    public void TestSha256CreateNamed() { var h = SHA256.Create("SHA256"); } // Noncompliant
    public void TestSha384CreateNamed() { var h = SHA384.Create("SHA384"); } // Noncompliant
    public void TestSha512CreateNamed() { var h = SHA512.Create("SHA512"); } // Noncompliant

    public void TestMd5Cng()        { var h = new MD5Cng(); }                     // Noncompliant
    public void TestSha1Cng()       { var h = new SHA1Cng(); }                    // Noncompliant
    public void TestSha1Csp()       { var h = new SHA1CryptoServiceProvider(); }  // Noncompliant
    public void TestSha256Cng()     { var h = new SHA256Cng(); }                  // Noncompliant
    public void TestSha256Csp()     { var h = new SHA256CryptoServiceProvider(); }// Noncompliant
    public void TestSha384Cng()     { var h = new SHA384Cng(); }                  // Noncompliant
    public void TestSha384Csp()     { var h = new SHA384CryptoServiceProvider(); }// Noncompliant
    public void TestSha512Cng()     { var h = new SHA512Cng(); }                  // Noncompliant
    public void TestSha512Csp()     { var h = new SHA512CryptoServiceProvider(); }// Noncompliant

    public void TestRipemd160Create()      { var h = RIPEMD160.Create(); }             // Noncompliant
    public void TestRipemd160CreateNamed() { var h = RIPEMD160.Create("RIPEMD160"); }   // Noncompliant
    public void TestRipemd160Managed()     { var h = new RIPEMD160Managed(); }          // Noncompliant

    public void TestMd5Csp()      { var h = new MD5CryptoServiceProvider(); }  // Noncompliant
    public void TestSha1Managed() { var h = new SHA1Managed(); }               // Noncompliant
    public void TestSha256Managed() { var h = new SHA256Managed(); }           // Noncompliant
    public void TestSha384Managed() { var h = new SHA384Managed(); }           // Noncompliant
    public void TestSha512Managed() { var h = new SHA512Managed(); }           // Noncompliant
}
