using System.Security.Cryptography;
public class DotNetECDsaTest {
    public void TestECDsaCreate() { var ecdsa = ECDsa.Create(); } // Noncompliant
}
