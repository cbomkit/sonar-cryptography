using System.Security.Cryptography;
public class DotNetRSATest {
    public void TestRsaCreate() { var rsa = RSA.Create(); } // Noncompliant
}
